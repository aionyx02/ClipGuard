# S8 不執行的語法驗證：`pwsh` AST、`bash -n` / `zsh -n`、cmd tokenizer、`osacompile`

- 日期：2026-11-24　平台：macOS（Darwin 27.2，arm64）
- 版本：PowerShell 7.7.0、`/bin/bash` 3.2.57、`/bin/zsh` 5.9、`osacompile`（系統內建）
- Spike 程式在暫存資料夾（不合併）：`psparse-server.ps1`（JSONL parser server）、`bench.py`、`cmdtok.py`（cmd tokenizer 原型，60 行）、`parse.sb`（`sandbox-exec` profile）。
- 方法：所有測試 payload 都是無害的 `New-Item` / `touch <scratch>/marker-N`、`Get-Date`、`echo`、`example.invalid` 網址。每次 parse-only 檢查後確認 marker 不存在。**全部測試（含 200 筆 benchmark）都沒有產生任何 marker**。

## 結論：可行，但「parse-only」不等於「零副作用」

| Shell | 不執行？ | 成本 | 結論 |
|---|---|---|---|
| PowerShell `Parser::ParseInput` | ✅ 不執行任何指令 | 常駐 server：每筆 median 0.10 ms（p95 0.20 ms）；冷啟動 median 86 ms（p95 101 ms） | 採用常駐 server。**會讀檔**（`using module`），要 sandbox |
| `bash -n` | ✅ | median 3.2 ms（p95 4.0 ms），每筆一個行程 | 採用。macOS 的 bash 3.2 **不檢查 `$(...)` 內部**，會漏抓錯誤 |
| `zsh -f -n` | ⚠️ 不執行指令，但**會 fork、會讀檔** | median 4.2 ms（p95 5.3 ms） | 採用，但一定要在 sandbox ＋ timeout 下跑 |
| cmd.exe | 沒有 parser | 自寫 tokenizer：約 20 µs/筆 | 只能做「結構檢查」，約 3–5 人天 |
| `osacompile` | ✅ 不執行 `do shell script`、JXA | 每筆一個行程 | 可用，但**會啟動 `tell application` 指定的 App** |

## 1. PowerShell

**有沒有執行**（`ParseInput` 與 `ParseFile` 都測過，marker 都沒出現）：`$(...)`、`& { }`、`Invoke-Expression "..."`、`powershell -EncodedCommand <b64>`、字串內 `"$(...)"`、`[ValidateScript({...})]`、`class` 靜態初始值、`using namespace`、`#requires -Modules`、DSC `Configuration`。

**例外，parse 時會碰到檔案系統：**
- `using module <路徑或名稱>`：parser 會**讀取並解析**該模組來解析型別（`class B : Foo {}` 在模組存在時 0 錯誤，不存在時 `TypeNotFound`）。實測模組本身的 `.psm1` 程式碼和 manifest 的 `ScriptsToProcess` **都沒有執行**，`Get-Module` 也沒有載入。依名稱時會搜尋 `$env:PSModulePath`。
- `using assembly <名稱>`：會嘗試載入組件（`using assembly System.Xml` 回報 `ErrorLoadingAssembly`）。用實際存在的 DLL 路徑測，AppDomain 組件數量沒有增加，但仍是 parse 時的檔案 IO。
- **Windows 上的風險**（macOS 無法驗證）：`using module \\host\share\x.psm1` 可能在 parse 時連 SMB，洩漏 NTLM hash。對策：validator 只在 Linux / macOS 跑，並在 sandbox 裡擋網路。另外 `PSModulePath` 要指向空目錄。
- 深度巢狀（20000 層括號）會回報 `ScriptTooComplicated`，**不會讓行程 crash**。

**縱深防禦：**
- `-ExecutionPolicy` 在非 Windows 平台**不會生效**（`Get-ExecutionPolicy -List` 全部是 `Unrestricted`），沒有用處。
- Constrained Language Mode 會擋掉 parser 本身的呼叫（`CannotCreateTypeConstrainedLanguage`），所以不能用。payload 只會被當成字串交給 parser，不會進入任何執行路徑。真正的防線是 OS sandbox。
- 啟動參數用 `-NoProfile -NonInteractive -File server.ps1`，並設定 `POWERSHELL_TELEMETRY_OPTOUT=1`、`DOTNET_CLI_TELEMETRY_OPTOUT=1`。

**cmd 風格的 payload**：`cmd /c echo hi ^& del x & powershell -c Get-Date`、`set x=%PATH% && echo !x! | findstr a > nul`、`curl ... | bash` **全部 0 錯誤**（`&` 在 PS7 是背景執行運算子，`%`、`!` 只是一般字元）。所以 pwsh 說 ok 對 cmd / bash payload 沒有任何意義，**一定要先判斷 payload 屬於哪個 shell 再送給對應的 validator**。混合型的 payload：先用 cmd tokenizer 切出指令；遇到 `powershell` / `pwsh` 時取出 `-c` / `-Command` 的參數，或把 `-EncodedCommand` 的值用 base64 → UTF-16LE 解碼，再遞迴送進 pwsh validator（最多 5 層，和核心的解混淆上限一致）。結果 = 外層 cmd 結構 ok **且** 所有內層都 ok。

## 2. bash / zsh `-n`

18 個案例在 `bash -n`、`zsh -n`、`sh -n` 下，用 stdin 和 `-c` 兩種方式各跑一次，marker 都沒出現：`$(...)`、backtick、`<(...)`、here-doc 裡的 `$(...)`、`eval`、`alias` 後立刻使用、`source`、`$(( $(...) ))`、`${x:=$(...)}`、`a[$(...)]=1`、重新導向目標裡的 `$(...)`、`trap`、函式定義後呼叫、`coproc`。zsh 另外測了 glob qualifier `*(e:'...':)`、`=(...)`、`${(e)...}`，也都沒有執行。

**陷阱：**
- **zsh `-n` 還是會展開參數位置的 command substitution**：在禁止 fork 的 sandbox 下，`echo $(true)` 會出現 `zsh: fork failed`（但 `x=$(true)` 不會）。fork 出來的子行程在 NO_EXEC 下不會 exec（用禁止 exec 的 sandbox 驗證過，沒有 marker）。**`$(<file)` 真的會讀檔**：`echo $(</dev/zero)` 跑 2.6 秒後出現 `fatal error: out of heap memory`；讀不存在的檔案會回報 `no such file`。巢狀 5000 層的 `$(` 會逾時（10 秒），50000 層會 segfault（rc -11）。→ zsh 一定要 timeout、記憶體上限，而且 sandbox **要允許 fork、禁止 exec**（禁止 fork 會讓所有 `$(...)` 被誤判成錯誤）。
- **`bash -n`（3.2）不檢查 `$(...)` 和 backtick 裡面**：`echo $(if true; then)` 回傳 rc 0，zsh 則回傳 1。CI 應該改用 bash 5.x（Linux 內建）；在 macOS 上也可以用 zsh 的結果交叉比對。
- 兩者都不檢查算術（`$((1+))` rc 0）、`eval "..."` 和 `bash -c "..."` 裡的字串、缺少結尾的 here-doc（rc 0）。字串裡的指令要像 pwsh 一樣遞迴取出來另外驗證。
- 結果跟 parse 時的選項有關：`ls !(x)` 在 bash 是錯誤（沒開 `extglob`），在 zsh 是 ok。
- 啟動檔：zsh 不加 `-n` 時會 source `$ZDOTDIR/.zshenv`（對照組有產生 marker）；加了 `-n` 之後雖然讀了，但沒有執行。保險起見一律用 `zsh -f -n`、`bash --norc --noprofile -n`，再加上 `env -i`（清掉 `BASH_ENV`、`ENV`、`ZDOTDIR`）。payload 一律從 stdin 傳入，不要放在 argv。

## 3. cmd.exe：自寫 tokenizer

cmd 沒有不執行的語法檢查，加上它非常寬鬆（引號沒有關閉也照樣執行），所以「語法正確」只能定義為**結構正確**：
1. 前處理：`^` 跳脫（在引號外才有效）、行尾 `^` 接續、`"` 開關狀態（引號沒關只給警告）；辨識 `%var%`、`%var:~a,b%`、`%var:x=y%`、`%%i`、`%~dp0`、`%1`、`!var!`。**不做變數代入**，由偵測引擎自己的解混淆處理。
2. 運算子：`&`、`&&`、`||`、`|`，以及 `n>`、`>>`、`<`、`2>&1` 等重新導向。錯誤：開頭或連續出現運算子、結尾懸空的 `|` / `&&` / `>`、重新導向沒有目標。
3. 區塊：`(`、`)` 要成對（`)` 只有在區塊裡才是運算子）；`if ... (...) else (...)`、`for [/f|/l|/r|/d] %x in (...) do ...` 的形狀檢查。
4. 子指令：`cmd /c|/k`、`powershell`、`start`、`call` 的參數交給遞迴 validator。

原型 `cmdtok.py` 只有 60 行，11 個案例中能正確區分 `echo hi |`、`&& echo x`、`if ... (echo b` 少一個括號、`for` 沒有 `do`，也能接受 `c^u^r^l`、`%COMSPEC:~-16,1%`、`2>&1 >nul | more`，速度約 20 µs/筆。**估計**：完整版（含 `if`/`for` 文法、`call :label`、delayed expansion 的 `^!` 規則、500 筆語料測試）在 Rust 或 Python 約需 3–5 人天；做到與真實 cmd 逐位元組一致則不可行。建議：在 Windows CI runner 上，用 `cmd /c` 執行 `echo` 化的對照組（把每個指令換成 `rem`）來校準 tokenizer，但**這只能用語料，絕不能拿紅隊 payload 來跑**。

## 4. macOS `osascript`

- `osascript -s` 只是**輸出格式**選項（`h/s/o/e`，見 man page），`osascript` 一定會執行，**禁止使用**。
- `osacompile -o /dev/null -e '...'` 只編譯：`do shell script "touch marker"`（包括寫在 `on run` 裡）、JXA（`-l JavaScript`，含 IIFE 與 `ObjC.import`）都沒有產生 marker。語法錯誤時 rc=1，並有錯誤碼（`-2741`、`-2740`、JXA `-2700`）。
- **副作用**：`tell application "TextEdit" ...` 在編譯時**把 TextEdit 啟動了**（原本沒有在跑，之後出現 pid 22444），為的是讀取它的 scripting dictionary。App 不存在時 rc=0（可能還會跳出「Where is …?」對話框）。→ 只能在 sandbox 裡跑並禁止 `process-exec`，或者先把 `tell application "X"` 改寫成 `tell application id "invalid"`；也可以只在 macOS CI 上一次性的 VM 裡跑。

## 5. Sandbox 設計（Phase 5 呼叫方式）

所有 validator 都在**獨立行程**裡執行，`redteam/` 的 Python 只透過 stdin/stdout 交換 JSONL，不在同一個行程裡 parse：
- 環境：`env -i PATH=/usr/bin:/bin HOME=<tmp>/home TMPDIR=<tmp>/t PSModulePath=<tmp>/empty`；cwd 設為空的暫存目錄；payload 只走 stdin。
- 限制：每筆 timeout（pwsh 2 秒、sh 2 秒、zsh 2 秒）、`RLIMIT_CPU`、`RLIMIT_NOFILE`、輸出上限；Linux 加 `RLIMIT_AS` 512 MB（macOS 的 `RLIMIT_AS` 不可靠，改由看門狗監看 RSS）。逾時或 crash 視為 `ok=false, error=ValidatorCrash`，**不能當成通過**；server 要自動重啟。
- macOS：`sandbox-exec -f parse.sb`：`(deny network*)`、`(deny file-write*` 除了暫存目錄以外`)`、`(deny process-exec` 除了 validator 本身以外`)`。實測 pwsh server、`bash -n`、`zsh -n` 都能在下面正常運作（zsh 要允許 fork）；對照組的 `touch` 被擋（`Operation not permitted`）。`sandbox-exec` 已經 deprecated 但仍可用，只用在開發機。
- CI（Linux）：容器 `--network none --read-only --tmpfs /tmp --pids-limit 64 --memory 512m --cap-drop ALL`，用非 root 使用者；或 `bwrap --unshare-all`。pwsh 用 Linux 版，順便避開 Windows UNC 的風險。

## 建議的 `redteam/` validator 架構

```
redteam/validate/
  router.py       # 判斷 shell：pwsh / sh / zsh / cmd / applescript；混合型先用 cmd tokenizer 切開
  pwsh_server.py  # 管理常駐的 pwsh（psparse-server.ps1），JSONL {id,src} -> {id,ok,errors[]}
                  #   每 N=5000 筆或 crash / 逾時就重啟；回應的 id 要和送出的相符
  posix.py        # bash --norc --noprofile -n / zsh -f -n，每筆一個行程，stdin 傳入
  cmd_tokenizer.py# 結構檢查，純函式（之後可以搬到 Rust core 共用）
  osa.py          # 只在 macOS：osacompile -o /dev/null，在 sandbox 內執行
  recurse.py      # 取出 -EncodedCommand / -c / bash -c / eval 字串再驗證，最多 5 層
  sandbox.py      # env -i + rlimit + timeout + sandbox-exec / bwrap 包裝
```
回傳 `pydantic` 模型 `SyntaxVerdict{shell, ok, errors[], inner[]}`。MCP 的 `validate_syntax` 只在 `--profile redteam` 下開放，結果只回傳錯誤 ID 和位置，不回傳 payload 原文。200 筆 benchmark 中，常駐 pwsh 的總成本約為 190 ms 啟動 + 20 ms，冷啟動則要 17 秒，所以一定要常駐。

## 風險

- **把「parse 成功」當成「會被執行」**：pwsh 接受 cmd 語法、bash 3.2 不看 `$(...)` 內部、cmd tokenizer 很寬鬆，三者都會產生假的 ok。router 判斷錯 shell 是最大的誤差來源，需要語料測試。
- **parse 時的 IO**：pwsh 的 `using module` / `using assembly`、zsh 的 `$(<file)`、`osacompile` 會啟動 App。全部靠 sandbox 擋，不能靠 validator 自己。
- **DoS**：zsh 巢狀、`/dev/zero`；pwsh 有 `ScriptTooComplicated` 保護，但常駐行程仍要看門狗。
- **Windows 未驗證**：UNC 路徑在 parse 時連線、Defender 對 payload 字串的反應都還沒測。建議 Phase 5 只在 Linux / macOS 跑 validator。
- `sandbox-exec` 已經 deprecated，未來的 macOS 可能移除。CI 以 Linux 容器為準。
