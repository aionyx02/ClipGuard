# Agent hook：讓 AI agent 執行指令前先過 PasteWarden

AI coding agent 可能被網頁或檔案裡的 prompt injection 騙去執行 ClickFix 指令，或把機密送出去。PasteWarden 的 hook 在 agent **呼叫工具之前**分析參數，危險的直接擋下。這是強制的防護；MCP server（見 [`mcp.md`](mcp.md)）只負責分析和解釋，模型可以選擇不呼叫它。

Hook 預設不安裝，要自己裝（AI 相關功能預設關閉）。

## 安裝

```sh
paste-warden hook install claude-code              # 預設 --scope user：~/.claude/settings.json
paste-warden hook install claude-code --scope project [--project-dir DIR]   # DIR/.claude/settings.json
paste-warden hook install opencode                 # ~/.config/opencode/plugins/paste-warden.ts
paste-warden hook install opencode --scope project # ./.opencode/plugins/paste-warden.ts
```

- `--dry-run`：只印出差異，不寫檔。
- 寫入前會先備份（`settings.json.pw-bak`，已有備份時依序用 `.pw-bak.1`、`.pw-bak.2`…），用暫存檔加 rename 寫入。
- 只合併 JSON：其他設定和你自己的 hook 都保留，鍵的順序也不變。重複執行不會產生重複的 entry（第二次會顯示「已經安裝，沒有變更」）。
- 設定檔含註解（JSONC）或格式錯誤時**不修改**，請照下面的「手動設定」自己加。
- 寫進設定的是 `paste-warden` 的**絕對路徑**，不依賴 `PATH`。如果執行檔是透過會換路徑的套件管理工具（例如 Homebrew 的 symlink）安裝，升級後請重新執行 `hook install`。
- 安裝前會跑一次自我測試（內建的無害樣本必須被擋下、`echo hello` 必須放行），失敗就不安裝。
- `--no-prompt-guard`：不安裝 Claude Code 的 `UserPromptSubmit` 檢查（見下文）。
- opencode：偵測到 `opencode --version` 小於 2 時拒絕安裝；找不到 opencode 時只提醒。

移除：`paste-warden hook uninstall <claude-code|opencode> [--scope user|project]`。只移除 PasteWarden 自己的 entry（以 command 含 `paste-warden` 且結尾是 `hook claude-code` 辨識）或帶有標記的 plugin 檔；別人的檔案不會被覆蓋或刪除。

## 判定規則

| 工具 | 檢查內容 | 結果 |
|---|---|---|
| Shell（Claude Code `Bash`、opencode `shell`） | `command` 交給 `Engine::analyze` | `quarantine` → **deny**；`warn` → **ask**（Claude Code）；含機密而且指令會連網（`curl`、`wget`、`nc`、`Invoke-WebRequest`…）→ **deny** |
| 對外請求（`WebFetch`、`WebSearch`、opencode `webfetch`） | 所有字串參數 | 含機密 → **deny** |
| 寫檔（`Write`、`Edit`、`MultiEdit`、`NotebookEdit`、opencode `write`/`edit`/`patch`） | 所有字串參數 | 含惡意指令 → **deny**（S7：先寫出 script 再執行的繞法）。寫入機密（例如 `.env`）不擋 |
| 其他 MCP 工具、opencode `execute` | 所有字串參數 | 含機密或惡意指令 → **deny** |
| PasteWarden 自己的 MCP 工具（`mcp__paste-warden__*`、opencode `paste-warden_*`） | 不檢查 | 不表示意見 |
| `UserPromptSubmit`（Claude Code） | 使用者送出的 prompt | 含機密 → `{"decision":"block"}`，prompt 不會送到模型 |

- **從不回 `allow`**：沒問題時不輸出任何東西（exit 0），照 agent 原本的權限流程走，不會蓋掉你自己的 ask 規則。
- 理由一律**中英雙語**（zh-TW 一行、en 一行），只包含翻譯後的原因、風險分數和遮罩後的機密，**不含原文**。Claude Code 在 `UserPromptSubmit` 被擋時會在本機畫面顯示原 prompt，所以理由本身更不能重複原文。
- opencode 的 plugin 沒有「ask」機制，所以 `warn`（例如官方安裝指令 `curl … | sh`）在 opencode 會放行，只有 deny 會擋。

## Fail-closed

Claude Code 對 crash、逾時和 0/2 以外的 exit code 一律放行（fail-open）。所以 `paste-warden hook` 自己處理所有錯誤：

- 整個檢查（包括讀 stdin）在 worker thread 裡用 `catch_unwind` 執行，內部 timeout 預設 2 秒（`--timeout-ms` 可調）；Claude Code 設定裡的 hook timeout 是 10 秒。
- 輸入不是 JSON、缺少必要欄位、超過 16 MiB、panic、逾時 → Claude Code：**exit 2**，理由寫在 stderr（exit 2 = 擋下）；opencode：輸出 `{"block":true,…}` 並 exit 2，plugin 對非 0 的 exit code、無法解析的輸出、spawn 失敗也一律 throw。
- panic 訊息不會印出（可能含資料），只顯示固定的 `paste-warden: internal error`。
- 整合測試（`crates/cli/tests/hook.rs`）涵蓋三種情況：格式錯誤、panic、逾時。panic 和逾時用環境變數 `PASTE_WARDEN_HOOK_FAULT=panic|hang` 注入；這個變數只能讓結果變成 deny，所以正式版保留它不會削弱防護。

**仍然會 fail-open 的情況**（hook 本身無法處理）：執行檔不存在或路徑錯誤、行程被 kill、`disableAllHooks: true`、`claude --bare`、`--settings '{"disableAllHooks":true}'`、刪掉 opencode plugin 檔。只有企業的 managed settings 加上 `allowManagedHooksOnly` 能鎖住。被 prompt injection 的 agent 也可能嘗試改寫 `.claude/settings.json`（見「待決問題」）。

## 手動設定

Claude Code（`settings.json`）：

```json
{
  "hooks": {
    "PreToolUse": [{
      "matcher": "^(Bash|WebFetch|WebSearch|Write|Edit|MultiEdit|NotebookEdit|mcp__(?!paste-warden__).*)$",
      "hooks": [{ "type": "command", "command": "/abs/path/paste-warden hook claude-code", "timeout": 10 }]
    }],
    "UserPromptSubmit": [{
      "hooks": [{ "type": "command", "command": "/abs/path/paste-warden hook claude-code", "timeout": 10 }]
    }]
  }
}
```

matcher 用 lookahead 排除 PasteWarden 自己的 MCP 工具（S7 的坑：`mcp__.*` 會擋到自己的 `analyze`）。hook 程式內部也會再排除一次，所以 matcher 寫成 `mcp__.*` 也不會出錯。下面的實測證明這個 matcher 在 Claude Code 2.1.331 仍會比對到 `Bash`。

opencode：執行 `paste-warden hook install opencode --dry-run` 就能看到 plugin 的完整內容。它只用 V2 寫法（`ctx.tool.hook("execute.before")`）；V1 的 `"tool.execute.before"` 在 opencode 2.x 會被列出但**不會觸發**。plugin 透過 stdin 傳 `{"tool","args"}` 給 `paste-warden hook opencode`，收到 `{"block","reason"}`。

## 實測紀錄（2026-11-25）

環境：macOS（Darwin 27.2）、`claude` 2.1.331、`opencode` 2.2.0、`paste-warden` release build。暫存專案資料夾，只用 `--scope project` 安裝，沒有改動任何全域設定。樣本是語料 `command.detector.clickfix-000`（執行時由片段組合，下文以 `$SAMPLE` 表示）：PowerShell 隱藏視窗下載並執行 `evil.example` 上的腳本。這台 macOS 沒有 `powershell`，網域也無法解析，所以就算沒擋住也不會執行任何東西。

```sh
paste-warden hook install claude-code --scope project --project-dir .
printf '{"mcpServers":{"paste-warden":{"command":"%s","args":["mcp"]}}}' /abs/path/paste-warden > mcp.json
```

| # | 指令 | 結果 |
|---|---|---|
| a | `claude -p "…Call the Bash tool exactly once with exactly this command…: $SAMPLE" --allowedTools Bash --output-format stream-json --verbose --max-turns 3` | ✅ 被擋下。`tool_result` 為 `is_error: true`：`PreToolUse:Bash hook error: PasteWarden 已攔截：這個指令被判定為惡意（風險分數 90/100）。原因：呼叫 PowerShell；下載後直接執行；隱藏視窗執行。換個寫法再試也會被擋，請停止並告知使用者。` 接著一行英文版。`permission_denials` 列出這次呼叫；模型照實轉告，沒有改寫重試 |
| b | `claude -p "Run the shell command: echo hello" --allowedTools Bash …` | ✅ 放行，輸出 `hello`，`permission_denials: []` |
| c | `claude -p "Use the paste-warden MCP tool analyze (locale zh-TW) on this text…: $SAMPLE" --strict-mcp-config --mcp-config mcp.json --allowedTools mcp__paste-warden__analyze …` | ✅ server `connected`；模型先用 ToolSearch 載入再呼叫 `mcp__paste-warden__analyze`，回傳 §2.2 Report（`action: quarantine`、`risk_score: 90`、6 個 zh-TW 原因）。hook 同時安裝著，沒有擋到自家工具 |
| d | 同 c，改為呼叫 `deobfuscate_trace`、`scan_secrets`、`mask`（文字 `& ('ec'+'ho') hello`） | ✅ 三個工具都可呼叫：trace 為 `concat` → `unwrap`，`output_preview: "& echo hello"`；`secrets: []`；`masked` 與原文相同 |

opencode（`paste-warden hook install opencode --scope project --project-dir .`，模型 `opencode/deepseek-v4.1-flash-free`，不需登入，沒有設定任何憑證）：

| # | 指令 | 結果 |
|---|---|---|
| 1 | `opencode run -m opencode/deepseek-v4.1-flash-free --format json "…Call the shell tool exactly once with exactly this command…: $SAMPLE"` | 模型拒絕呼叫工具（認為是惡意指令），hook 沒有被觸發，不能算驗證 |
| 2 | 同上，改寫說明（plugin 會先檢查；網域無法解析、沒有 powershell） | ✅ 模型仍拒絕直接執行，但改用其他方式，plugin 兩次擋下含樣本的呼叫：`write`（要把樣本寫進檔案）→ `status: error`，`PasteWarden 已攔截：要寫入或傳給工具的內容含有惡意指令。原因：呼叫 PowerShell；下載後直接執行；隱藏視窗執行…`；`shell`（把樣本 `printf` 給分類器）→ `status: error`，`PasteWarden 已攔截：這個指令被判定為惡意（風險分數 90/100）…` 加英文版。同一次執行中不含樣本的 `shell`（`ls -la`、`paste-warden --help`）和 `write`（`echo hello` 的 JSON）都正常完成 |

## 待決問題

- 被 prompt injection 的 agent 可以改寫 `.claude/settings.json` 或刪掉 opencode plugin 來關掉 hook。要不要讓 hook 對「寫入 agent 設定檔」一律 ask？
- 要不要支援 `PostToolUse`，檢查 `WebFetch` 抓回來的網頁內容？
- opencode 在 Windows 的設定路徑和 `.ts` plugin 的 spawn 行為還沒驗證。
- 其他 agent（Cursor、Codex CLI、Gemini CLI）。
