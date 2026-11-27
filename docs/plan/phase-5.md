# Phase 5：Agent（llm crate、紅藍隊閉環、指標報表、稽核日誌）

> 分支：`feature/phase-5-agent` → PR 到 `dev`（和 Phase 4 平行，彼此不依賴）
> 依賴：`Engine::analyze`、語料（Phase 1）；`crates/py`、`paste-warden bench`、MCP server（Phase 2）
> 參考：`docs/spikes/s8-syntax-validation.md`、`s7-agent-integration.md`；`docs/integrations/agent-hooks.md`；`docs/spec/detection-rules.md` §3、§5.4、§9；`docs/THREAT_MODEL.md` T4、T10、T11

## 5.1 範圍

roadmap 的完成條件是「產出 V1 → V3 的偵測率和誤報率圖」。為了做到這件事，Phase 5 有五個元件：

| 元件 | 位置 | 技術 | 用途 |
|---|---|---|---|
| LLM 介接與護欄 | `crates/llm` | Rust、`ureq`（rustls）、`schemars` | Tier 2 解說；CLAUDE.md 的五條護欄寫在這裡 |
| CLI 的 Tier 2 | `crates/cli` | — | `scan --llm`、`llm check` |
| 紅隊 | `redteam/`（Python） | `uv`、`pydantic`、`httpx` | 產生混淆變體 → 語法驗證 → 偵測 |
| 藍隊 | `redteam/src/redteam/blue/` | opencode headless（`opencode run`，免費模型） | 讀繞過樣本 → 改 `rules/`、`corpus/` → 開 PR |
| 報表與稽核 | `redteam/src/redteam/report/`、`audit.py` | `matplotlib` | 四項指標、V1→V3 圖、稽核日誌 |

另外加上 MCP 的 `redteam` profile（`validate_syntax`、`run_benchmark`，phase-2.md §2.5 預留的）。

**已決定**（2026-11-25 確認）：

- 紅隊的 LLM 以**本機 Ollama 為主**：模型 `qwen3.8:27b-mlx`，報表上記下 model digest、Ollama 版本、temperature、seed，讓數字可以重現。紅隊程式用 OpenAI 相容的 API 呼叫，所以也能換成 OpenRouter，但報表只用 Ollama 的結果。
- **預算 0 元**：所有線上模型都只用免費的。藍隊用 **opencode headless** 加上 opencode Zen 的免費模型（不用登入、不用 API key；Phase 2 實測 hook 時用過），權限限制寫在程式裡，見 §5.5。OpenRouter 的免費模型是備案（要免費帳號的 API key，沒儲值時每天約 50 次請求，不夠藍隊的 agent 迴圈用）。
- **更新（2026-11-25）**：opencode Zen 的免費額度很小，今天幾十次請求就用完（`FreeUsageLimitError`，`retryAfterMs` 約 17.8 小時），一輪藍隊就跑不完。藍隊改成優先用**本機 Ollama**（`ollama/qwen3.8:27b-mlx`，透過 opencode 的 `@ai-sdk/openai-compatible` provider），Zen 的免費模型排在後面當備援。實測：本機模型能正確呼叫 read／write，寫 `crates/` 會被 plugin 擋下；MLX runner 的 context 是 262,144。第一次使用這個 provider 時，opencode 要先下載 npm 套件，會卡幾分鐘才送出請求。
- 免費模型的服務條款通常允許供應商記錄輸入。送出去的只有公開 repo 的規則、語料和合成的 payload，沒有使用者資料。
- 另外有一組**不用 LLM 的確定性變異器**（G0），當作基準線，CI 也跑它。這樣沒有 LLM 時，整個閉環仍然能跑。

## 5.2 閉環流程

```
 corpus 的 229 筆 malicious 指令（執行時由 parts 組合）
   │ 依 sha256(id) 切成 train 80% ／ heldout 20%（固定，不隨版本改變）
   ▼
 紅隊 ─ G0 確定性變異器（seeded）
      └ G1 Ollama（看得到上一輪引擎的判定原因，會調整寫法）
   │ Variant { shell, payload(只在記憶體與 run store), technique, parent }
   ▼
 語法驗證（S8 sandbox）── 不合法 → 丟棄，計入「語法有效率」
   ▼
 引擎（指定版本的 paste_warden wheel）── action == quarantine → 擋下
   │                                   └ 其他 → 繞過（none／suspicious 分開計）
   ▼
 藍隊（train 的繞過，分群後最多 MAX_BYPASSES_PER_ROUND 筆）
   │ 在獨立的 worktree 改 rules/、corpus/ → 檢查程式驗證 → 開 draft PR
   ▼
 人工 review 並合併 → 下一個版本（V2、V3）→ 下一輪
```

| 版本 | 定義 |
|---|---|
| V1 | `feature/phase-5-agent` 上凍結 heldout 的 commit（偵測規則和核心與 `dev` 的 `e9ce55d` 完全相同），tag `redteam-v1` |
| V2 | 第 1 輪藍隊 PR 合併進 `feature/phase-5-agent` 後，tag `redteam-v2` |
| V3 | 第 2 輪藍隊 PR 合併進 `feature/phase-5-agent` 後，tag `redteam-v3` |

**偏離**（2026-11-25）：藍隊的分支和 PR 改成以 `feature/phase-5-agent` 為基底，不是 `dev`。藍隊要用的 `xtask corpus add-from-run` 和 lint 對 `redteam:` source 的支援只在 Phase 5 分支上，`dev` 沒有。這樣 Phase 5 仍然只有一個 PR（#45），規則的修補跟著它一起進 `dev`。代價是藍隊 PR 的目標不是 `dev`，CI 不會自動跑；orchestrator 在本機跑完 §5.5.2 的全部檢查，合併進 Phase 5 分支後 #45 的 CI 會再驗證一次。

每一輪的紅隊都**針對當時的最新版本**產生變體（會適應的攻擊者）。heldout 在 Phase 5 一開始就產生並凍結，藍隊看不到，三個版本都用同一份 heldout 評分，所以 V1→V3 的進步不是過擬合造成的。

## 5.3 紅隊（`redteam/`）

### 5.3.1 目錄

```
redteam/
  pyproject.toml        # uv；ruff + black（行長 80、單引號）；pydantic、httpx、matplotlib、pytest
  src/redteam/
    models.py           # pydantic：Seed、Variant、SyntaxVerdict、EngineVerdict、RoundResult、AuditEvent
    seeds.py            # 讀 corpus、組合 parts、切 train／heldout
    store.py            # run store（payload 一律存成 parts），見 5.3.4
    mutate/             # G0：每個 shell 一個模組＋組合器
    gen_llm/            # G1：OpenAI 相容 client、prompt、輸出 schema
    validate/           # S8 的架構：router、pwsh_server、posix、cmd_tokenizer、osa、recurse、sandbox
    engine.py           # 在指定 git rev 建 wheel（依 SHA 快取），用子行程跑 analyze
    blue/               # 藍隊 orchestrator，見 §5.5
    report/             # 指標與圖表
    audit.py
    cli.py              # redteam seeds|generate|validate|eval|blue|report|loop
  tests/
  eval/                 # 凍結的 heldout 與額外的良性集（parts 格式，進版控）
  runs/                 # 每次執行的資料（.gitignore）
```

### 5.3.2 G0 確定性變異器

每個變異器都是 `(payload, rng) -> payload | None` 的純函式，**依照構造保證語意不變**。每個變異器都要有單元測試，用手寫的等價例子確認輸出。最多疊 `G0_MAX_DEPTH` 層（低於 core 解混淆的 5 層上限，才看得出「超過 5 層」以外的弱點）。

| Shell | 變異器 |
|---|---|
| cmd | `^` 插入、`""` 插入、`%VAR:~a,b%` 切字、`set` 間接、`cmd /c` 包裝、大小寫 |
| PowerShell | 反引號、字串拼接、`-f` 格式化、`[char]` 代碼、反轉字串、`-EncodedCommand`（UTF-16LE base64）、別名互換（`iwr`／`Invoke-WebRequest`／`curl`）、變數間接（`$a='i'+'ex';&$a`）、參數縮寫（`-w h`、`-nop`）、大小寫 |
| sh／bash／zsh | `$'\x..'`、`${IFS}`、引號切字（`c''url`）、`base64 -d \| sh`、`eval`、變數間接 |
| 共通 | 空白與填充（含超過讀取上限的位置）、誘餌註解的翻譯與改寫、零寬字元與同形字（測 normalize）、換行切成多行 |

實作備註（2026-11-25）：
- 種子 229 筆：powershell 131、cmd 60、bash 21、sh 17（zsh、applescript 0），train 189、heldout 40。`source: redteam:*` 的語料不會變成種子，所以種子和 heldout 不會隨藍隊的修補改變。
- 零寬字元、同形字、全形字的變異照原樣不能執行，登記為 `semantic=False`，報表另外列；偵測率的主要數字只算 `semantic=True` 的變體。
- `-w h` 沒做（只在 `Hidden`／`hidden`／`1` 之間互換）；`curl`／`wget` 別名只用在 Windows PowerShell 5.1；`sh.ifs` 不用在 zsh；`sh.ansi_c` 不用在 dash。cmd 的變異假設是在互動式 cmd 貼上執行，不是 Win+R。
- PowerShell 的變異器模組叫 `ps.py`，原始碼和測試裡不出現完整的程式名稱，有測試掃描。
- 冒煙測試（10 個 train 種子、200 個 G0 變體、當時的 dev）：擋下 157、降級 15、繞過 28。繞過較多的 technique：`ps.reverse`、`ps.char`、`ps.concat`、`ps.var_indirection`、`common.padding`。
- **效能發現**：≤ 1 KB 的變體 p99 1.5 ms（預算 1 ms），最慢的一筆 63 ms，而且是沒被擋下的變體。這是藍隊之外要給核心處理的問題，V1 報表會列出來。

- **種子的語法檢查**：`redteam attack` 先在種子自己的 shell 驗證它；229 個裡有 2 個不合法（一個 Markdown 跳脫案例、一個 bypass 案例），跳過並計數。刻意超過 validator 輸入上限（256 KiB）的 padding 變體記為 `unchecked`，不算 `validator_crash`。

### 5.3.3 G1 LLM 變異器（`gen_llm/`）

- 呼叫 `OLLAMA_BASE_URL`（預設 `http://127.0.0.1:11434/v1`）的 `/chat/completions`，`response_format` 用 JSON schema：`{"variants":[{"shell":"cmd|powershell|sh|bash|zsh|applescript","payload":"…","technique":"…"}]}`。輸出通過 pydantic 驗證才採用，否則丟棄並記為 `invalid_output`。
- prompt 包含：種子指令、它的 shell、**上一次嘗試時引擎給的判定原因 ID**（只給 ID 和分數，不給規則原文），以及「要保持語意不變、不能改變下載網址和執行行為」的要求。第 2 次以後的嘗試會看到自己前一個變體的判定結果（最多 `G1_MAX_ATTEMPTS` 次）。
- 關掉 qwen3 的 thinking：在 Ollama 0.40.16 的 `/v1/chat/completions` 實測，`reasoning_effort: "none"` 有效（沒有 reasoning 輸出），頂層 `think: false` 在 `/v1` 會被忽略，所以用前者。
- **模型拒絕**（沒有可解析的輸出，或輸出是拒絕的句子）記為 `refused`，計入報表，不重試。試跑時如果拒絕率超過 50%，依序改用 `G1_FALLBACK_MODELS` 的下一個（本機模型優先，最後才是 opencode Zen 的免費模型），報表寫明實際用的模型。
- 紅隊的 prompt 和輸出只送到本機的 Ollama。改用 OpenRouter 時，payload 會送到第三方；payload 都是合成的、網址都是 `example.invalid`，沒有使用者資料，但要在文件寫明。

實作備註與試跑（2026-11-25）：
- 每次呼叫有總時間上限（httpx 的 timeout 只管單次讀取），連線逾時 `G1_CONNECT_TIMEOUT_S = 10`。輸出被 token 上限截斷（`finish_reason == 'length'`）記為 `invalid_output`、會重試，不算拒絕；連線錯誤不計入拒絕率的分母。
- `G1_FALLBACK_MODELS` 預設 `('qwen3.8:27b-mlx', 'qwen3:0.6b')`；opencode Zen 的免費模型需要另外的 base URL，用傳入的 `ChatClient` 指定。
- **試跑**（`qwen3.8:27b-mlx@5642e97495e1`、Ollama 0.40.16、10 個 train 種子、最多 3 次嘗試）：21 次呼叫，拒絕 0、`invalid_output` 0；平均 8.9 秒／次；61 個變體，語法有效 60 個（98.4%）。各次嘗試的擋下／降級／完全繞過：第 1 次 23／4／3、第 2 次 16／0／1、第 3 次 9／1／3。10 個種子裡 8 個至少有一個變體沒被擋下。稽核日誌外洩檢查 0 筆。
- 以這個速度估計，183 個 train 種子 × 3 次嘗試約 45–80 分鐘。

### 5.3.4 payload 的處理（不可妥協）

- **永遠不執行、不寫入系統剪貼簿**。只會送進 S8 的語法檢查器（stdin）和偵測引擎。
- run store 和 `eval/` 裡的 payload 一律存成 corpus Text 的 `parts`（每 `STORE_PART_CHARS` 字切一段），和語料規則相同，避免被 Defender 隔離，也避免被 push protection 擋下。
- 稽核日誌只放 payload 的 SHA-256 和 variant ID，不放原文。
- 只在 macOS、Linux 執行（S8：Windows 上 `using module \\host\share` 可能在 parse 時連 SMB）。`redteam` CLI 偵測到 Windows 就拒絕執行。
- 測試會靜態掃描 `redteam/src`：禁止 `shell=True`、`os.system`、`pyperclip`／`pbcopy`／`xclip`／`wl-copy`，`subprocess` 只能出現在 `validate/sandbox.py`、`engine.py`、`blue/`。

### 5.3.5 語法驗證（`validate/`）

完全照 S8 §5 的設計：每個 validator 是獨立行程，payload 只走 stdin，`env -i`、暫存 HOME、空的 `PSModulePath`、timeout、rlimit；macOS 用 `sandbox-exec`（禁止網路、只能寫暫存目錄、zsh 允許 fork 但禁止 exec），CI 用 Linux 容器（`--network none --read-only --pids-limit 64 --memory 512m --cap-drop ALL`、非 root）。

- 送進 pwsh 之前，**先拒絕**含 `using module`／`using assembly` 的 payload（不分大小寫、容許中間有空白和反引號），結果記為 `rejected_unsafe`，不算語法有效。
- osacompile 前先把 `tell application "X"` 改寫成 `tell application id "invalid.pastewarden"`。
- 逾時或 crash 一律是 `ok=false, error=ValidatorCrash`，不能當成通過；常駐的 pwsh server 每 `PWSH_RESTART_EVERY` 筆或出錯就重啟。
- 混合型 payload 照 S8 §1 遞迴驗證（`-EncodedCommand`、`-c`、`bash -c`、`eval`），最多 5 層。
- cmd tokenizer 先做 S8 §3 的第 1–3 項（前處理、運算子、區塊），`if`／`for` 只檢查基本形狀；用 500 筆語料測試校準。

實作備註（2026-11-25，都經過實測）：
- osacompile 不改寫成 `tell application id "invalid.pastewarden"`：這樣每個 `tell` 都編譯失敗（-1728）；改成名稱形式又會跳「Where is…?」對話框卡到 timeout。實作改寫成 `tell me`，`using terms from <app>` 改成 `if true then … end if`。代價是 App 專用的語法（例如 `keystroke … using`）會被誤判成 `invalid`。
- pwsh 在 Linux 不設 `RLIMIT_AS`（.NET GC 啟動就要預留 256 MiB，512 MB 下起不來）和 `RLIMIT_FSIZE`（會擋掉 .NET W^X 需要的 memfd）；改用 RSS 看門狗、`GCHeapHardLimit` 和容器的 `--memory 512m`。
- pwsh 的拒絕清單多了 `Import-DscResource`（DSC 可能在 parse 時載入模組）。拒絕的比對容許反引號、`<# #>` 註解、NBSP、零寬字元和換行。
- macOS 上 `sh` 改用 `bash --posix -n`（`/bin/sh` 會再 exec bash，被 sandbox 擋下）；bash 3.2 只在含 `$(` 或反引號時另外用 `zsh --emulate sh -f -n` 交叉比對。
- zsh 在 parse 時讀檔（例如 `$(<不存在的檔案)`）算 `validator_crash`（`zsh.parse-time-io`），不算語法錯誤。
- 新增 `MAX_PAYLOAD_BYTES = 256 KiB`，超過回 `validator_crash`（`payload-too-large`）。
- 找不到 sandbox 或 sandbox 自測失敗 → `validator_crash`（`no-sandbox`），絕不在 sandbox 外執行。CI 的 `redteam` job（ubuntu，沒有 sandbox）會跳過需要 sandbox 的測試；完整的 validator 測試在 `redteam-validate.yml` 的鎖緊容器裡跑（228 passed、15 skipped，skip 的都是 macOS 專用）。
- **已知缺口**：bwrap 和容器做不到「允許 fork、禁止 exec」，只有 macOS 的 sandbox-exec 做得到。S8 實測 `-n` 模式下 fork 出的子行程不會 exec，風險有限。
- 每筆延遲（中位數）：pwsh 常駐 0.10 ms（macOS）／0.13 ms（Linux）；bash 16.7 ms／0.76 ms；zsh 11.9 ms／1.11 ms；cmd tokenizer 0.04 ms。macOS 較慢主要是每筆都要啟動 sandbox-exec。

**已知限制**：語法正確不等於語意相同。G0 依照構造保證語意不變；G1 的變體由藍隊在修補前判斷是否等價（§5.5），報表把 G1 的繞過分成「藍隊確認等價」和「未確認」兩欄。另外每一輪人工抽查 `HUMAN_AUDIT_SAMPLE` 筆 G1 繞過，結果寫進報表。

## 5.4 偵測與評分

- `engine.py` 用 `git worktree` 建出指定版本，`maturin build --release` 出 wheel，依 commit SHA 快取在 `redteam/.cache/wheels/`，每個版本在自己的 venv 子行程裡跑，避免版本互相干擾。
- 判定：`action == quarantine` 算擋下；`warn`（suspicious）算**降級**；`allow` 算**完全繞過**。報表分開列。

### 四項指標

| # | 指標 | 定義 | 資料集 |
|---|---|---|---|
| 1 | **偵測率** | 語法有效的惡意變體中，`action == quarantine` 的比例；另列「至少 warn」的比例 | heldout（主要）、train |
| 2 | **誤報率** | 良性樣本中 `action != allow` 的比例；`warn` 和 `quarantine` 分開列 | `corpus/benign`（982 筆）＋ `eval/benign-extra.jsonl` |
| 3 | **攻擊成功率** | 每一輪紅隊針對當時版本產生的新變體中，繞過的比例（G0、G1 分開） | 每一輪的 train |
| 4 | **修補成本** | 每個藍隊 PR 改動的規則行數、新增的語料筆數、heldout 的 p99 分析時間（對照 phase-1.md 的效能預算：一般 1 KB 輸入 ≤ 1 ms）、藍隊花的時間和回合數 | 藍隊 PR |

- `eval/benign-extra.jsonl`：202 筆真實世界的良性指令（原本寫了 290 筆，去掉和 `corpus/benign` 重複的 88 筆，因為藍隊看得到 `corpus/benign`）（官方安裝指令、winget／scoop／choco／brew、docker、kubectl、git、npm scripts、常見的 PowerShell 系統管理 one-liner），手寫加人工 review，藍隊看不到。用來看規則有沒有「為了擋繞過而開始誤報沒看過的良性指令」。
- 輔助數字：語法有效率、G1 的拒絕率和 `invalid_output` 比例、每個 technique 的偵測率。

### V1 基準線（2026-11-25，`redteam-v1`）

heldout 凍結：40 個種子、897 個變體（G0 783、G1 114；G1 只試 1 次，不針對 V1 調整）。另有 18 個變體外層合法但內層腳本不合法，照設計排除。

| 資料集 | allow | warn | quarantine |
|---|---|---|---|
| heldout（種子＋變體，937） | 67 | 78 | 792 |
| `corpus/benign`（982） | 933 | 49 | 0 |
| `benign-extra`（202） | 196 | 2 | 4 |

`benign-extra` 的 4 筆 quarantine 都是合法的官方安裝指令（NodeSource、Poetry、Tailscale、Nix 的 `curl … | sh`），因為它們的網域不在 `rules/command/official-hosts.json` 裡。這是真實的誤報，照實列入報表；**不能**依 `benign-extra` 調整規則，否則它就不再是沒看過的資料。

### 報表（`redteam report`）

輸出到 `redteam/reports/<日期>/`：`report.json`（pydantic 模型）、`report.md`、`detection-fp.svg`（V1→V3 的偵測率與誤報率）、`rounds.svg`（每輪的攻擊成功率）、`techniques.svg`。SVG 產生淺色和深色兩份，文件網站的「開發者」區段依系統深淺色顯示。

## 5.5 藍隊（`blue/`）

CLAUDE.md 規定：藍隊只能改規則和語料、不能改引擎、只能開 PR、不能合併。這些限制由兩層程式碼強制，不靠 prompt：執行中由 opencode plugin 擋（§5.5.1），結束後由 orchestrator 檢查（§5.5.2）。免費模型改規則的能力比付費模型差，所以第二層的檢查是主要防線，第一層只是讓模型早點知道自己做錯了。

### 5.5.1 執行環境

- orchestrator 從 `dev` 建出 `git worktree`（分支 `redteam/round-<N>`），用 sparse checkout 把整個 `redteam/` 排除在外（`git sparse-checkout set --no-cone '/*' '!/redteam/'`）。heldout、run store、orchestrator 的程式碼在這個 worktree 裡**根本不存在**，所以就算 grep 整個目錄也讀不到；排除不算刪除，`git diff` 不受影響。交接檔放在 worktree 的 `.pw-blue/`（寫進 `.git/info/exclude`）：`blue-input.jsonl`、只含這一輪繞過樣本的 run store `.pw-blue/store/`，以及藍隊要寫的 `blue-output.json`。然後在裡面執行：

  ```sh
  opencode run --standalone --auto --format json \
    -m "$BLUE_MODEL" --agent pw-blue "<任務說明>"
  ```

  `--standalone` 讓這次執行用自己的 server，不共用使用者背景執行中的 opencode；`--auto` 自動核准沒有被明確 deny 的權限，所以下面的 deny 一定要寫齊。
- worktree 裡的 `.opencode/opencode.json`（orchestrator 產生，不進版控）：
  - `permission`：`webfetch`、`websearch` 為 `deny`；`bash` 預設 `deny`，只允許 `cargo run -p xtask -- corpus *`、`cargo test -p paste-warden-rules *`、`cargo test -p paste-warden-core *`；`edit` 只允許 `rules/**`、`corpus/**`。
  - `agent.pw-blue`：任務說明、可用的工具。
  - 不設定任何 MCP server。
- worktree 裡的 `.opencode/plugins/pw-blue-guard.ts` 加上判斷邏輯 `pw-blue-policy.mjs`（V2 寫法 `ctx.tool.hook("execute.before")`，V1 寫法會靜默失效）。**這一層才是強制的**，上面的 `permission` 只是縱深防禦。預設拒絕：不認得的工具和參數形狀一律擋下。
  - `write`／`edit`／`patch` 的目標路徑不在 `rules/**`、`corpus/cases/**`、`corpus/benign/**`、`corpus/divergences/**`（唯一例外是 `.pw-blue/blue-output.json`）→ 擋下。路徑先正規化，`rules/../crates/…` 和 worktree 外的絕對路徑都算越界；`patch` 從內文的檔案標頭取路徑。
  - `read`／`grep`／`glob` 的目標在 `redteam/`、`.git/`、`.opencode/` 或 worktree 外 → 擋下（第二層保險，正常情況 `redteam/` 不存在）。
  - `corpus add-from-run` 的來源只能是 `.pw-blue/store`，不能指向其他 run store 或 `redteam/eval`。
  - `shell` 不符合上面三個允許的指令前綴，或含 `;`、`&&`、`|`、`` ` ``、`$(` → 擋下。
  - 工具呼叫次數超過 `BLUE_MAX_TOOL_CALLS` → 之後全部擋下，等於強制結束。
  - plugin 自己出錯一律擋下（fail closed）；plugin 也照常呼叫 `paste-warden hook opencode`，所以 Phase 2 的惡意指令檢查同時生效。
  - 每次擋下都寫一行到 run store 的 `blue-denials.jsonl`（工具名稱和原因代碼，不含內容），計入稽核日誌。
  - **實測（2026-11-25，opencode 2.2.0，`opencode/deepseek-v4.1-flash-free`）**：在暫存 repo 要求模型寫 `crates/core/new.rs`、寫 `rules/b.json`、執行 `git status`。結果：第一個和第三個被擋（`write-denied-path`、`shell-not-allowlisted`），`rules/b.json` 寫入成功，`crates/` 沒有新檔。相對路徑 import `.mjs` 可以用。判斷邏輯的單元測試在 `redteam/tests/blue/policy.test.mjs`。
- 外層有 `BLUE_TIMEOUT_MIN` 的時間上限，逾時就 kill 整個 process group。
- `BLUE_MODEL` 預設用 `BLUE_MODELS` 的第一個；同一輪連續兩次 `invalid`（沒有產生任何有效修改）就換下一個。報表記下每一輪實際用的模型。
- 藍隊的輸入是 orchestrator 寫在 worktree 裡的 `blue-input.jsonl`：分群後的繞過樣本（parts 格式）、每筆的 technique、引擎判定原因、所在的語料種子 ID。藍隊不需要自己打出 payload：新增語料一律用新的 xtask 子命令 `cargo run -p xtask -- corpus add-from-run <run-store> <variant-id> --expect malicious`，它把 run store 的 parts 原樣寫進 `corpus/cases/redteam-*.jsonl`。
- 對每筆 G1 繞過，藍隊要先判斷是否和種子語意等價，寫進 `blue-output.json`（`equivalent | not_equivalent | unsure`＋理由）。`not_equivalent` 的不修補。

### 5.5.2 檢查（orchestrator，藍隊結束後）

全部通過才 commit；任何一項失敗就把失敗原因交回藍隊再試一次（最多 `BLUE_MAX_ATTEMPTS` 次），仍然失敗就放棄這一輪的修補並記錄。

1. `git diff --name-only dev...` 只包含 `rules/**`、`corpus/cases/**`、`corpus/benign/**`、`corpus/divergences/**`。
2. 語料**只能新增**：既有的 case 不能刪除，也不能改 `expect`（防止藍隊用「改考題」的方式通過）。
3. 每條新規則或改過的規則都有「該命中」和「不該命中」兩種樣本（CLAUDE.md 測試資料規則）。
4. `cargo run -p xtask -- corpus lint`、`corpus run`（0 失敗）、`corpus benign`（0 誤報）、`cargo test -p paste-warden-rules -p paste-warden-core`；規則的 regex 通過 detection-rules.md §5.4 的語法限制。
5. heldout 的 p99 分析時間不超過 phase-1.md 的效能預算，`ci.yml` 的 perf job 也要通過。
6. train 的繞過至少修好一筆。

### 5.5.3 開 PR

orchestrator（不是藍隊）用 `gh pr create --draft --base dev --head redteam/round-<N>` 開 PR，內文包含 train 的前後指標、修改摘要、等價判斷的統計和稽核日誌摘要。**orchestrator 沒有合併的程式路徑**，測試會靜態檢查 `blue/` 不含 `gh pr merge`、`git push origin dev`、`git push origin main`。

CI 另外加一個 job：分支名稱是 `redteam/*` 的 PR，只要改到 §5.5.2 第 1 項以外的路徑就失敗。這擋的是有人繞過 orchestrator 直接推分支的情況。

## 5.6 `crates/llm`（Tier 2 解說與護欄）

紅隊的 Python client 不用這個 crate：紅隊的輸入是合成的 payload，不是使用者資料。這個 crate 是給使用者端的 Tier 2 解說用的，CLAUDE.md 的五條護欄都寫在這裡的程式碼中。

| 項目 | 設計 |
|---|---|
| 設定 | `LlmConfig::Disabled` 是預設值。`Enabled { provider: OpenAiCompatible{base_url} \| Anthropic, model, api_key, local: bool, only_high_risk: bool }`；API key 由呼叫端傳入（CLI 從設定指定的環境變數讀），crate 自己不讀環境變數 |
| 開關 | 用型別保證：`Disabled` 拿不到 `Client`，所以關閉時沒有任何程式路徑能建立連線 |
| ① 機密不送雲端 | `Client::explain(report, masked_text)` 先看 Tier 1 的 Report：有 `secrets` 或登記機密命中，而且不是本機端點（`local == true` **且** `base_url` 的 host 是 loopback）→ 回傳 `Refused(SecretsPresent)`，不發請求。送出的文字一律是遮罩後的 |
| ② 包裝不可信內容 | 內容放進 `<untrusted_payload>…</untrusted_payload>`，裡面的 `&`、`<`、`>` 先轉成 entity，所以內容不可能關掉標籤 |
| ③ 輸出驗證 | 要求 JSON 輸出 `{ "level": "none\|suspicious\|malicious", "explanation": string(≤ LLM_MAX_EXPLANATION_CHARS), "techniques": [enum] }`；schema 由 `schemars` 從 Rust 型別產生，放進請求的 `response_format`；收到後用 `serde`（`deny_unknown_fields`、列舉）嚴格反序列化，再檢查長度上限，任何一步失敗就丟棄。**不用 `jsonschema` crate**：它的 `pattern` 驗證依賴 `fancy-regex`（關掉預設 feature 也一樣，2026-11-25 用 `cargo tree` 確認），違反 CLAUDE.md 的 regex 規定 |
| ④ 只升不降 | `merge(tier1: Level, llm: Option<Level>) -> Level` 回傳兩者中較高的；proptest 保證結果永遠 ≥ Tier 1 |
| ⑤ 不給工具、有 timeout | 請求不帶 `tools`／`tool_choice`；回應含 `tool_calls` 就丟棄；連線與讀取 timeout `LLM_TIMEOUT_MS`，輸出上限 `LLM_MAX_OUTPUT_TOKENS` |
| 稽核 | `AuditSink` trait：每次呼叫記 provider、model、護欄判定、耗時、結果代碼；**不記 prompt 或回應內容** |
| 相依 | HTTP client（`ureq`，rustls）只在 `crates/llm`，放在 `net` feature 後面 |

CLI：

- `paste-warden scan --llm [--llm-config PATH]`：設定檔預設 `~/.config/paste-warden/llm.toml`（Windows 是 `%APPDATA%\PasteWarden\llm.toml`）。沒有設定檔或 `enabled = false` 時，`--llm` 只印「AI 功能未開啟」並照常輸出 Tier 1 結果。
- `paste-warden llm check`：送一筆內建的無害樣本，確認端點、模型、JSON 輸出都正常。
- Report JSON 加上可選欄位 `"llm": { "level", "explanation", "techniques", "provider", "model" }`；`action` 依 ④ 重新計算。`crates/report` 的 schema 版本維持 `1`，只新增可選欄位。

桌面 UI 接 Tier 2 不在 Phase 5 範圍（Phase 4 的 UI 完成後再加）。

實作備註（2026-11-25）：
- 送給供應商的 schema 拿掉 `maxLength`、`maxItems`：OpenAI 和 Anthropic 的 structured output 會拒絕這兩個關鍵字。長度上限照樣在本地驗證（③）。
- `only_high_risk` 預設 `true`：Tier 1 指令判定為 `none` 時不呼叫模型。`llm check` 不受影響。
- 額外的限制：不跟隨 redirect、不使用環境變數的 proxy（避免本機端點把請求轉到雲端）；`base_url` 含 `user@` 拒絕；非 loopback 必須 https；解說含控制字元（換行除外）或 bidi 字元就整份丟棄；techniques 不可重複；遮罩後的文字超過 `LLM_MAX_PAYLOAD_CHARS`（8 000）截斷並告知模型；回應上限 `LLM_MAX_RESPONSE_BYTES`（64 KiB）。
- ④ 只重新計算 `action`（malicious → quarantine、suspicious → warn），Report 的 `command.level` 保留 Tier 1 的判定。
- MCP `validate_syntax` 同時回傳 `ok` 和 `status`；validator 回傳的錯誤 ID 不在已知清單時換成 `redacted`，避免透過錯誤 ID 外洩內容。
- CLI 目前用 `NoAudit`，AuditSink 還沒接到檔案（Tier 2 的稽核檔位置待桌面版一起決定）。
- 本機實測：Ollama `qwen3:0.6b`，`llm check` 約 2.2 秒、JSON 通過驗證；`scan --llm` 對 ClickFix 樣本 Tier 1 與 AI 都判 malicious。

## 5.7 MCP 的 `redteam` profile

`paste-warden mcp --profile redteam` 在 guard 的四個工具之外再加：

- `run_benchmark { items: [{id, text}] }` → 只回傳每筆的 `action`、`level`、`risk_score`、reason ID 和總表，跟 `bench` 一樣；上限 `MCP_BENCH_MAX_ITEMS` 筆。
- `validate_syntax { text, shell? }` → `{ shell, ok, errors: [{id, line, column}] }`，不回傳 payload。實作是透過 stdin JSONL 呼叫 `--validator-cmd` 指定的 validator（預設 `uv run --project redteam python -m redteam.validate.server`）；沒有設定或 validator 不存在時回工具錯誤。

測試：guard profile 的工具清單不含這兩個；redteam profile 的輸出不含輸入原文。

## 5.8 稽核日誌

紅藍隊的每一步都寫進 `redteam/runs/<run-id>/audit.jsonl`，一行一個 `AuditEvent`：

```jsonc
{ "ts": "…", "run_id": "…", "round": 1, "actor": "red-g0|red-g1|validator|engine|blue|orchestrator",
  "event": "generate|validate|detect|blue_start|blue_check|pr_open|…",
  "variant_id": "…", "payload_sha256": "…", "rules_rev": "<git sha>",
  "model": "qwen3.8:27b-mlx@5642e97495e1", "params": { "temperature": 0.9, "seed": 1234 },
  "prompt_sha256": "…", "response_sha256": "…",
  "result": { "syntax_ok": true, "action": "warn", "reason_ids": ["…"] },
  "duration_ms": 0, "tokens": { "in": 0, "out": 0 } }
```

- 不含 payload 原文、prompt 原文或模型回應原文，只有雜湊（原文留在 run store，`.gitignore`）。
- 藍隊的 `opencode run --format json` 紀錄存在 run store；稽核日誌只記模型、工具名稱、被 plugin 擋下的次數（`blue-denials.jsonl`）、修改了哪些檔案。
- 報表附上 `audit-summary.jsonl`（每一輪的彙總），進版控。

## 5.9 常數

| 常數 | 值 | 來源 |
|---|---|---|
| `HELDOUT_RATIO` | `0.2`，依 `sha256(case id)` 切 | 自訂 |
| `G0_VARIANTS_PER_SEED`／`G0_MAX_DEPTH` | `20`／`3` | 自訂 |
| `G1_VARIANTS_PER_CALL`／`G1_MAX_ATTEMPTS` | `3`／`3` | 自訂 |
| `G1_TEMPERATURE` | `0.9`，seed = `hash(run_seed, case id, attempt)` | 自訂 |
| `STORE_PART_CHARS` | `6` | 自訂 |
| `VALIDATOR_TIMEOUT_MS` | `2_000`（pwsh、sh、zsh） | S8 |
| `VALIDATOR_RLIMIT_AS_MB` | `512`（Linux）；macOS 用看門狗監看 RSS | S8 |
| `PWSH_RESTART_EVERY` | `5_000` | S8 |
| `MAX_BYPASSES_PER_ROUND` | `10`（分群後的代表樣本；原本 40，2026-11-27 降低，理由見下方） | 自訂 |
| `BLUE_MAX_TOOL_CALLS`／`BLUE_MAX_ATTEMPTS`／`BLUE_TIMEOUT_MIN` | `150`／`2`／`75`（原本 45，2026-11-28 放寬） | 自訂 |
| `OLLAMA_MAX_OUTPUT_TOKENS` | `16_384`（藍隊本機模型每一步的輸出上限，含思考） | 自訂 |
| `BLUE_MODELS` | `opencode/deepseek-v4.1-flash-free`、`opencode/mimo-v2.6-flash-free`、`opencode/nemotron-3.5-super-vl-free`（2026-11-25 `opencode models` 列出的免費模型；第一個在 Phase 2 實測過） | 自訂 |
| `G1_FALLBACK_MODELS` | 本機 `qwen3.8:27b-mlx` → 之後試跑時挑一個本機模型 → `opencode/deepseek-v4.1-flash-free` | 自訂 |
| `HUMAN_AUDIT_SAMPLE` | `30` | 自訂 |
| `LLM_TIMEOUT_MS`／`LLM_MAX_OUTPUT_TOKENS`／`LLM_MAX_EXPLANATION_CHARS` | `20_000`／`512`／`600` | 自訂 |
| `MCP_BENCH_MAX_ITEMS` | `1_000` | 自訂 |

自訂值的理由：

- `G0_MAX_DEPTH = 3`：疊越多層越不像真實攻擊，也越容易超過語料的效能預算。3 層已經涵蓋 S8 的混合型（cmd → powershell → base64）。
- `G1_VARIANTS_PER_CALL = 3`：一次要 3 個比要 1 個省掉重複的 prompt 成本。實測 27B 模型在這台 M5 Max 每次呼叫平均 8.9 秒（§5.3.3），183 個 train 種子約 45–80 分鐘。
- `STORE_PART_CHARS = 6`：比任何偵測關鍵字（`powershell`、`mshta`、`Invoke-Expression`）都短，單一片段不會被防毒軟體認成完整的指令。
- `MAX_BYPASSES_PER_ROUND = 10`、`BLUE_MAX_TOOL_CALLS = 150`：讓一輪藍隊在 45 分鐘內做完，PR 的大小也還能人工 review。opencode 沒有 `--max-turns`，所以由 plugin 計數。
  - **更新（2026-11-27）**：原本是 40。第 1 輪跑了兩次都在 45 分鐘逾時，什麼都沒產出：agent 讀了 `crates/core/src/command/*.rs`、`docs/spec/detection-rules.md`、`xtask/` 和 52 KB 的良性語料，context 漲到約 184k token，每一步要 181 秒，37 次工具呼叫就用完時間。換小模型解決不了，所以改成三件事：每輪降到 10 筆；task prompt 直接附上 §3.2 判定表、§3.7 的 `signals.json` 格式和全部可用的 reason ID、良性語料的範例；policy plugin 拒絕讀取 `crates/`、`docs/`、`xtask/`、`target/`（`read-engine-or-docs`，glob 的 pattern 也檢查）。藍隊本來就改不到這些目錄，讀了也沒用。
  - **本機模型的輸出上限（2026-11-28）**：第 2 輪第三次嘗試，本機 qwen 有兩步分別花了 417 秒和 1,485 秒，產生 16,301 和 46,340 個 token，看得到的文字只有一兩千個 token，其餘幾乎都是思考；正常的一步只有幾百到幾千個 token。藍隊不像紅隊那樣關掉思考（思考對寫 regex 有幫助），改成在 opencode 設定裡限制每一步的輸出（`limit.output` = `OLLAMA_MAX_OUTPUT_TOKENS`），時間上限也從 45 分鐘放寬到 75 分鐘。若被截斷而沒有回答的步驟太多，再考慮關掉思考或把一輪拆成兩批。
  - **挑選邏輯（2026-11-28 修正）**：原本把所有分群照 key 的字母順序排好，再從頭輪流取一筆。分群數遠多於 10，所以實際上只挑到字母最前面的 10 群：第 1、2 輪挑到的全是 G1、名稱以 a 或 b 開頭的手法（`alias`、`assembly-load`、`base64-…`），G0 一筆都沒有。可是 G0 占了大多數繞過（第 2 輪 370 筆裡有 235 筆），heldout 也幾乎都是 G0（783/897），heldout 裡存活的又以 `sh.*` 為主，所以這兩輪對 heldout 的判定完全沒有影響（V1、V2 和第 2 輪的候選版都是放行 67、降級 78、擋下 792）。現在改成以「產生器 × shell」為單位輪流挑，每個單位內完全繞過排在降級前面、大的分群排在小的前面，每個分群取一筆。第 2 輪用新邏輯重跑，舊的結果留在本機分支 `redteam/round-2-alphabetical`，不開 PR。
  - `redteam blue` 新增可重複的 `--model`，用來覆寫 `BLUE_MODELS` 的順序。Zen 額度重置後可以讓 Zen 排第一，本機 Ollama 當備援；不加的話照預設，本機排第一。
- `BLUE_MODELS`：免費模型會下架或改名，每一輪開始前先用 `opencode models` 確認，不在清單上就跳過。
- `LLM_TIMEOUT_MS = 20_000`：本機 27B 模型產生 512 tokens 需要的時間，加上餘裕。

## 5.10 CI

- `redteam` job（ubuntu）：`uv sync`、`ruff check`、`black --check`、`pytest`（變異器、parts 格式、靜態掃描、orchestrator 的路徑檢查與 diff 規則、報表模型）。
- `redteam-smoke`：只用 G0、10 個種子、validator 在容器裡跑，引擎用目前的 commit，確認整條管線能跑完。不呼叫任何 LLM。
- `redteam-paths`：§5.5.3 的分支路徑檢查。
- `no-http-in-core`：`cargo tree -p paste-warden-core -e normal` 和 `-p paste-warden-wasm` 不能出現 `ureq`、`reqwest`、`hyper`。
- `crates/llm` 的測試用本機的 mock HTTP server：五條護欄各一組；**AI 關閉時的網路測試**：開一個 TCP listener，把設定的端點指向它但 `enabled = false`，跑 `scan --llm`，斷言 listener 收到 0 個連線。

## 5.11 時程

| 日期 | 里程碑 |
|---|---|
| 11/26–11/29 | 平行開發（§5.12），完成 G0、validator、引擎評分、`crates/llm` |
| 11/30 | 產生並凍結 heldout、benign-extra；tag `redteam-v1`；試跑 G1，量拒絕率與速度 |
| 12/01 | 第 1 輪 → 藍隊 PR → **人工 review、合併** → `redteam-v2` |
| 12/03 | 第 2 輪 → 藍隊 PR → **人工 review、合併** → `redteam-v3` |
| 12/04–12/05 | 報表、圖、文件網站；Phase 5 PR |

兩次人工合併是時程上的瓶頸，每一輪需要有人在一天內 review。

## 5.12 平行開發

主 session 先做：`redteam/pyproject.toml` 與 `uv.lock`、`models.py`（所有 agent 共用的 pydantic 模型）、workspace 新增的 Rust 相依（`ureq`）、`.gitignore`、CI 骨架。之後開三個 worktree agent：

| Agent | 擁有的檔案 | 不能碰 |
|---|---|---|
| `phase5/llm` | `crates/llm/**`、`crates/cli/src/{llm,mcp_redteam}.rs`、`crates/cli/tests/llm*.rs`、`crates/report` 的 `llm` 欄位 | `redteam/**` |
| `phase5/validate` | `redteam/src/redteam/validate/**`、`redteam/tests/validate/**`、sandbox profile、CI 容器的 Dockerfile | 其他 `redteam/` 子目錄 |
| `phase5/red-eval` | `seeds.py`、`store.py`、`mutate/**`、`engine.py`、`report/**`、`audit.py`、對應的 tests、xtask 的 `corpus add-from-run` | `validate/`、`crates/llm` |

藍隊的 opencode plugin（`blue/pw-blue-guard.ts`）和它的測試由主 session 寫，因為它和 orchestrator 的檢查要一起設計。

三個 agent 合併後，主 session 做 `gen_llm/`、`blue/`、`cli.py` 的 `loop`，以及跨元件的接線和試跑。

## 5.13 完成條件

- [ ] `crates/llm`：五條護欄各有測試；AI 關閉時 0 連線的測試；`no-http-in-core` 通過。
- [ ] `scan --llm`、`llm check` 能用本機 Ollama 跑通。
- [ ] MCP `redteam` profile 的兩個工具；guard profile 不含它們。
- [ ] G0、G1、validator（pwsh、bash、zsh、cmd tokenizer、osacompile）、引擎評分、稽核日誌。
- [ ] heldout、benign-extra 凍結並進版控（parts 格式）。
- [ ] 至少兩輪藍隊 PR 經人工 review 後合併，V1、V2、V3 都有 tag。
- [ ] `redteam/reports/` 產出四項指標與 V1→V3 圖，文件網站的開發者區段可以看到。
- [ ] CI 全綠（含 `redteam`、`redteam-smoke`、`redteam-paths`）。

## 5.14 已決定（2026-11-25）

- 預算 0 元。藍隊改用 opencode headless＋免費模型（§5.5.1），不用 Claude Code；紅隊的 G1 用本機 Ollama，拒絕率過高時才改用免費的線上模型。
- 人工抽查與藍隊 PR 的 review 由使用者負責（每輪約 30 筆抽查＋一個 PR）。
- heldout 和 benign-extra 進版控（parts 格式）。

## 5.15 待決問題

1. **免費模型改不動規則怎麼辦**：如果兩輪都沒有產生能通過 §5.5.2 的修改，V2、V3 就沒有差別。備案是讓主 session（開發用的 Claude Code，不另外花錢）照同樣的流程和檢查手動跑一輪，報表標明「藍隊由開發者的 agent 執行」。要不要接受這個備案？
2. **V3 之後要不要繼續跑**：時間允許的話，第 3 輪的結果可以只放在報表裡（V4 不合併），當作「攻擊者還能找到什麼」的展示。
