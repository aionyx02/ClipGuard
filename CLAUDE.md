# PasteWarden（剪貼簿守門員）：給 agent 的說明

PasteWarden 把剪貼簿當成信任邊界，雙向防守：

- **進來**：ClickFix / FileFix 假驗證指令、Pastejacking、隱藏字元、錢包地址掉包，以及 AI agent 被網頁騙去執行指令
- **出去**：個資、API key、私鑰、助記詞、使用者登記的機密被貼出去

目前正在**用 Rust 全面重寫**。舊的 C# 版本在 Phase 0 刪除，只留在 git 歷史裡；它的功能清單已轉成 `corpus/` 的語料，**Rust 版必須通過全部語料**。

## 必讀

| 文件 | 用途 |
|---|---|
| `docs/plan/roadmap.md` | 架構、已定案的決策、各 Phase 範圍 |
| `docs/plan/phase-N.md` | **目前 Phase 的規格就是合約**。要偏離規格時，同一個 PR 裡更新規格並寫明原因 |
| `docs/spec/detection-rules.md` | 偵測行為的規格，P1–P7 原則和 §9 review 檢查清單照舊適用。改偵測行為前先改這份 |

## 工作流程

- 從 `dev` 開 `feature/phase-N-<slug>`，**每個 Phase 一個 PR** 到 `dev`。`main` 只接受來自 `dev` 的 PR，不要直接推 `dev` 或 `main`。
- Commit 用英文 conventional commits。
- 開始一個 Phase 之前，先確認上一個 Phase 的完成條件都達成了。
- 不確定的事寫進該 Phase 文件的「待決問題」，不要自行假設後默默實作。

## 架構紅線

### Rust 核心（`crates/core`、`crates/rules`）
- **純邏輯**：不做 IO、不讀環境變數、不碰時鐘（時間由呼叫端傳入）、不依賴任何 OS 或 GUI；`#![forbid(unsafe_code)]`。
- **必須能編譯到 `wasm32-unknown-unknown`**，CI 會檢查。
- **任何輸入都不能 panic、不能卡住**：fuzz target 要涵蓋所有公開入口。所有上限寫成具名常數（讀取長度、解混淆最多 5 層、解碼後的膨脹倍數、變數代入次數）。
- **只用 `regex` crate**（保證線性時間）。禁用 `fancy-regex`、`pcre2` 這類有回溯的引擎。規則檔語法限制見 `docs/spec/detection-rules.md` §5.4。
- **規則是資料**：偵測用的關鍵字、程式清單、官方網站清單、金鑰格式放在 `rules/`，引擎只寫通用邏輯。藍隊 agent 只能改規則和語料，不能改引擎。
- **位置一律用 UTF-8 byte offset**；到 JS / WASM 邊界才換成 UTF-16。
- **Core 不產生給人看的文字**：只回傳訊息 ID 和參數，由 UI 用 Fluent（`locales/{zh-TW,en}/*.ftl`）翻譯。

### 隱私（P3 / P4，不可妥協）
- 剪貼簿原文不寫檔、不寫 log、不放進錯誤訊息、不出現在通知；機密一律遮罩後才顯示。
- 記憶體裡的原文用 `zeroize`。登記的機密只存 HMAC-SHA256，**禁止**改用單純的 SHA-256。
- 預設零遙測。只有「競技場」和使用者自己啟用的 LLM 會連網。

### AI 功能預設關閉
- 預設只用本機的 Tier 1 引擎防禦。LLM 解說、agent hook、MCP server 都要使用者自己開啟或安裝。
- AI 功能關閉時，程式不能連到任何 LLM 端點，要有測試保證。

### LLM 護欄（寫在程式碼裡，不靠 prompt）
1. Tier 1 偵測到個資或金鑰時，程式直接拒絕呼叫雲端模型。
2. 不可信的內容包在 `<untrusted_payload>` 裡，並先跳脫掉標籤。
3. 輸出必須通過 JSON schema 驗證，失敗就丟棄。
4. **LLM 只能提高風險等級，永遠不能降低 Tier 1 的判定。**
5. 模型不能呼叫任何工具，並設定 timeout。

### Agent 與紅隊
- MCP server 和 CLI 只提供唯讀分析工具。**禁止提供讀取剪貼簿的工具**，否則被 prompt injection 的 agent 可以拿它偷走剪貼簿內容。工具輸出一律遮罩。MCP 只用 stdio，不開網路埠。
- 紅隊專用的工具（`validate_syntax`、`run_benchmark`）只有在 `--profile redteam` 時才開放。
- **真正的防護靠 hook**（強制執行）；MCP 只負責分析和解釋，因為模型可以選擇不呼叫它。
- 紅隊產生的 payload **永遠不執行、不寫入系統剪貼簿**，只能送進不執行的語法檢查器（`pwsh` AST、`bash -n`）和偵測引擎。
- 藍隊 agent 只能開 PR，不能合併。

### 平台與前端
- 桌面和行動版用 Tauri v2：權限寫在 `capabilities/*.json`，禁用 v1 API。
- Windows 用 `windows` crate；macOS 用 `objc2` 系列（禁用 `cocoa`），輪詢包在 `autoreleasepool` 裡。
- 前端用 React + TypeScript + Tailwind。注入網頁的 UI 用 Preact 或原生 JS，放在 Shadow DOM 裡。
- **所有 UI 都要跟隨系統的深淺色和語言**，設定裡也能手動切換（系統、淺色、深色；繁中、English）。注入網頁的 UI 跟隨 OS 設定，不跟隨網頁本身。
- 擴充功能和桌面程式之間可以互通（Native Messaging），但**只裝其中一個也必須完整運作**。

### Python（`redteam/`）
- 用 `uv` 管理，資料結構用 `pydantic`。
- 用 Ruff + Black：行長 80、單引號；設定寫在 `redteam/pyproject.toml`。

## 測試資料

- 只能用假資料：自己算出能通過檢查碼的號碼、發卡機構公開的測試卡號、執行時產生的假 key（`corpus/` 的 Text `rand`）。
- 網址一律用 `example.invalid`。**惡意指令樣本用片段儲存（Text 的 `parts`），執行時才組合**，否則會被 Defender 隔離。
- API key 樣本不能完整寫進任何檔案，否則會被 GitHub push protection 擋下。
- 每條規則都要有「該命中」和「不該命中」兩種樣本。

## 驗證指令

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build -p paste-warden-core --target wasm32-unknown-unknown
cargo run -p xtask -- corpus lint      # 語料格式與防外洩掃描（Phase 0 之後）
cargo run -p xtask -- corpus run       # 用 Rust 跑全部語料（Phase 1 之後）
pnpm -r lint && pnpm -r test      # Phase 3 之後
cd redteam && uv run ruff check && uv run pytest   # Phase 5 之後
```

## 命名

- Repo：`paste-warden`。顯示名稱：`PasteWarden`。中文名稱：剪貼簿守門員。
- Crate：`paste-warden-<name>`。執行檔：`paste-warden`。npm 套件：`@paste-warden/<name>`。
