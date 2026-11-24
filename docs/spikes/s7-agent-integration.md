# S7 Agent 介接：Claude Code / opencode hook、rmcp MCP server

- 日期：2026-11-24　平台：macOS（Darwin 27.2）
- 版本：`claude` 2.1.331、`opencode` 2.2.0、`rmcp` 3.11.0、Rust 1.100.0
- Spike 程式在暫存資料夾（不合併）：單一執行檔 `pw-spike`，子命令 `hook claude-code`、`hook opencode`、`mcp`。偵測邏輯是假的：輸入含 `PW_SPIKE_BLOCK` 就判定為惡意。

## 結論：可行

| 項目 | 結果 |
|---|---|
| Claude Code `PreToolUse` 擋 Bash | ✅ 被擋下，模型收到中英雙語理由，也照實轉告使用者 |
| Claude Code 放行正常指令（`echo hello`） | ✅ |
| Claude Code `PreToolUse` 擋 WebFetch、MCP 工具 | ✅ 兩者都會觸發；**subagent 裡的工具呼叫也會觸發** |
| Claude Code `UserPromptSubmit` 擋外送的 prompt | ✅ prompt 根本沒送到模型（0 次 API 呼叫） |
| rmcp stdio MCP server，Claude 呼叫 `analyze` | ✅ 回傳 `{"level":"safe","reasons":[]}`，含 `structuredContent` |
| opencode V2 plugin `execute.before` 擋 shell | ✅ 丟出 Error 就會擋下，模型看到理由 |
| opencode MCP（`mcp.servers`）呼叫 `analyze` | ✅ |
| opencode V1 寫法的 plugin（`"tool.execute.before"`） | ❌ 2.2.0 會列在 `plugin list` 裡，但 hook **不會觸發**，指令照樣執行 |

Claude Code 跑了 4 次 `claude -p`。opencode 的 Google provider 額度已用完（HTTP 402），改用不需登入的 `opencode/deepseek-v4.1-flash-free` 跑了 3 次，沒有設定任何憑證。所有指令都是 `echo`，網址用的是 `example.invalid`。

## Claude Code hook 合約

文件：<https://code.claude.com/docs/en/hooks.md>、`permissions.md`、`settings.md`

**stdin**（JSON）：共通欄位有 `session_id`、`transcript_path`、`cwd`、`permission_mode`、`hook_event_name`。在 subagent 裡觸發時另有 `agent_id`、`agent_type`。
- `PreToolUse` 另有 `tool_name`、`tool_input`、`tool_use_id`。`tool_input` 的內容：Bash 是 `{command, description, timeout?, run_in_background?}`；WebFetch 是 `{url, prompt}`；MCP 工具的 `tool_name` 格式是 `mcp__<server>__<tool>`，`tool_input` 就是工具參數。
- `UserPromptSubmit` 另有 `prompt`。

**拒絕的方式（建議）**：exit 0，並在 stdout 輸出：
```json
{"hookSpecificOutput":{"hookEventName":"PreToolUse",
  "permissionDecision":"deny","permissionDecisionReason":"<zh-TW>\n<en>"}}
```
- `permissionDecision` 可以是 `allow`、`deny`、`ask`、`defer`（`defer` 只在 `-p` 有效）。多個 hook 的結果衝突時，優先順序是 deny > defer > ask > allow。
- 不輸出任何東西並 exit 0，代表沒有意見，照一般權限流程走。**PasteWarden 不應該回 `allow`**，免得蓋過使用者自己的 ask 規則。
- exit 2：擋下，內容取自 stderr。其他非 0 的 exit code 是**不擋的錯誤，等於 fail-open**。所以 hook 內部一定要自己 catch 所有錯誤；spike 在 JSON 解析失敗時一律 exit 2。
- 頂層的 `decision: "block"` 在 PreToolUse 已經 deprecated，但 `UserPromptSubmit` 仍然用 `{"decision":"block","reason":"..."}`（已實測）。
- **`--allowedTools Bash` 不會繞過 hook**：hook 先於 allow 規則執行（已實測）。

**模型看到的內容**（實測，`tool_result` 的 `is_error: true`）：
```
PreToolUse:Bash hook error: PasteWarden 已攔截：此指令被判定為惡意（spike 標記 PW_SPIKE_BLOCK）。請勿改寫或繞過，請告知使用者。
PasteWarden blocked this command: ...
```
模型會轉告使用者，而且這次沒有嘗試改寫指令。`-p` 的 `result.permission_denials` 會列出被擋的呼叫。

`UserPromptSubmit` 被擋時，CLI 顯示 `UserPromptSubmit operation blocked by hook: <reason>\n\nOriginal prompt: <原文>`（`prompt_kept: false`），模型收不到。注意這則提示**會在本機畫面上顯示原文**，所以 reason 本身不能再重複原文。

**最小設定**（`.claude/settings.json`）：
```json
{"hooks":{
  "PreToolUse":[{"matcher":"Bash|WebFetch|mcp__.*",
    "hooks":[{"type":"command","command":"/abs/path/paste-warden hook claude-code","timeout":10}]}],
  "UserPromptSubmit":[{"hooks":[{"type":"command","command":"/abs/path/paste-warden hook claude-code","timeout":10}]}]
}}
```
- `timeout` 的單位是秒。實測 debug build 每次呼叫約 4 ms，所以啟動成本可以忽略。
- 專案的 `.claude/settings.json` 在 `-p` 模式**不需要信任提示**就會執行 hook。
- **坑**：matcher `mcp__.*` 也會擋到 PasteWarden 自己的 `analyze`（實測：分析一段惡意文字的請求反而被擋）。正式版的 matcher 要排除 `mcp__paste-warden__.*`，或者 hook 對自家工具直接放行。

**設定檔位置**（優先順序由高到低）：managed > `--settings` > `.claude/settings.local.json` > `.claude/settings.json` > `~/.claude/settings.json`（Windows 是 `%USERPROFILE%\.claude\settings.json`）。managed settings 的位置：macOS 是 `/Library/Application Support/ClaudeCode/managed-settings.json`，Linux 是 `/etc/claude-code/managed-settings.json`，Windows 是 `C:\Program Files\ClaudeCode\managed-settings.json`。

**MCP**：`claude --strict-mcp-config --mcp-config mcp.json --allowedTools mcp__pw__analyze`
```json
{"mcpServers":{"pw":{"command":"/abs/path/paste-warden","args":["mcp"]}}}
```
永久設定可以寫在專案的 `.mcp.json`，或執行 `claude mcp add`。Claude 會先用 ToolSearch 載入 `mcp__pw__analyze`，再呼叫它。

## opencode（V2）hook 合約

文件：<https://opencode.ai/docs/plugins/>、`/docs/build/plugins/server`、`/docs/mcp-servers/`。opencode 2.x 的 plugin API 和 1.x 不相容：`~/.config/opencode` 底下的 `@opencode-ai/plugin` 1.19.3 型別是舊版的，不要拿來參考。

**Plugin**（`.opencode/plugins/*.ts|js` 自動載入；全域是 `~/.config/opencode/plugins/`；設定檔的鍵名是 `"plugins"`）：
```ts
import { Plugin } from "@opencode/plugin"          // 由 opencode 執行檔內建提供，不需要 npm install
import { spawnSync } from "node:child_process"
export default Plugin.define({
  id: "paste-warden",
  async setup(ctx) {
    await ctx.tool.hook("execute.before", (event) => {
      // event: { tool, sessionID, agent, messageID, id, input }（input 可以修改）
      const r = spawnSync(BIN, ["hook", "opencode"], {
        input: JSON.stringify({ tool: event.tool, args: event.input }), encoding: "utf8", timeout: 10000 })
      if (r.status !== 0) throw new Error("PasteWarden hook failed")   // fail-closed
      const v = JSON.parse(r.stdout)
      if (v.block) throw new Error(v.reason)                           // 丟出 Error = 擋下
    })
  },
})
```
- 被擋時，工具的狀態是 `status: "error"`，`error` 就是我們給的 reason，模型看得到並會轉告使用者。
- 工具名稱是 `shell`（不是 `bash`）。MCP 工具是透過 `execute` 程式碼工具呼叫的（`tools.pw.analyze({...})`），**外層的 `execute` 和內層的 `pw_analyze` 都會觸發 hook**，所以掃描 `execute` 的 `code` 字串也是必要的。
- `pw-spike hook opencode` 是 spike 自己定的協定：stdin 收 `{tool,args}`，stdout 回 `{block,reason}`。正式版沿用這個格式，或改成和 Claude Code 相同的 JSON 都可以。
- 另一種做法是 `opencode.json` 裡的 `permissions: [{action:"shell", resource:"...", effect:"deny"}]`。它只支援 glob，不能做內容分析，只適合當作補充。

**MCP**（`opencode.json` 或 `.opencode/opencode.json`）：
```json
{"$schema":"https://opencode.ai/config.json",
 "mcp":{"servers":{"pw":{"type":"local","command":["/abs/path/paste-warden","mcp"]}}}}
```
V2 不再把 server 直接放在 `mcp` 底下，停用時用 `disabled`。`opencode mcp list` 會顯示「No MCP servers configured」，但實際 run 時可以用，這個指令的輸出不可信。

**設定檔位置**：全域是 `~/.config/opencode/opencode.json(c)`，專案是 `./opencode.json(c)` 或 `./.opencode/`，system 是 `/Library/Application Support/opencode`（macOS）或 `/etc/opencode`（Linux），而且 **system 的優先順序最高**。Windows 的位置未驗證。

## rmcp 3.11.0 最小 server

Feature：`rmcp = { version = "3.11.0", features = ["server","macros","transport-io","schemars"] }`，另外需要 `schemars = "1"`、`tokio`（`macros`、`rt-multi-thread`、`io-std`）。
```rust
#[derive(Deserialize, JsonSchema)] struct AnalyzeInput { text: String }
#[derive(Serialize, JsonSchema)]   struct AnalyzeOutput { level: String, reasons: Vec<String> }
#[derive(Clone)] struct Analyzer;            // 3.11 的 #[tool_handler] 預設呼叫 Self::tool_router()，不需要 router 欄位

#[tool_router]
impl Analyzer {
    #[tool(description = "...", annotations(read_only_hint = true, open_world_hint = false))]
    async fn analyze(&self, Parameters(p): Parameters<AnalyzeInput>) -> Json<AnalyzeOutput> { /* 只回 ID */ }
}
#[tool_handler]
impl ServerHandler for Analyzer {
    fn get_info(&self) -> ServerConfig {      // 3.x 回傳 ServerConfig（不是舊版的 ServerInfo）
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::from_build_env())
    }
}
// main: Analyzer.serve(rmcp::transport::stdio()).await?.waiting().await?;
```
- `Json<T>` 會自動產生 `outputSchema`，並回傳 `structuredContent` 加上一份文字版。
- 輸出只有 `level` 和訊息 ID，**不會回顯輸入**（已實測）。
- log 一律寫到 stderr，stdout 只能放協定訊息。

## 限制

1. **Hook 可以被使用者或專案關掉**：`disableAllHooks: true`、`claude --bare`、`--settings '{"disableAllHooks":true}'`、刪掉 plugin 檔，都能關掉。只有 managed settings 加上 `allowManagedHooksOnly` 才能鎖住，但那屬於企業部署，不在一般使用者的範圍。被 prompt injection 的 agent 理論上也能改寫 `.claude/settings.json`，所以要考慮讓 hook 同時檢查「寫入 agent 設定檔」這類動作。
2. **Agent 可以改寫指令**：這次模型很配合，但真正的惡意 payload 會被拆字、編碼、寫進檔案再執行（例如 `Write` 寫出 script，再用 `bash x.sh` 執行）。spike 的字串比對沒有意義，真正有用的是 core 的 normalize 和 deobfuscate；`Write`、`Edit` 的內容也要掃描。
3. **Fail-open 風險**：Claude Code 的 hook 在 exit 不是 0 也不是 2，或是逾時的時候會放行。執行檔崩潰或找不到路徑，等於沒有防護。
4. **MCP 只是建議**：模型可以不呼叫它，這符合 CLAUDE.md 的定位。
5. **opencode API 變動快**：V1 和 V2 的 plugin 完全不相容，裝錯版本時不會有任何警告。
6. hook 在 subagent 裡也會執行（實測 WebFetch），這是好事。但 `--bare` 會跳過所有 hook。

## Phase 2 建議設計

`paste-warden hook install <claude-code|opencode> [--scope user|project] [--dry-run]`：
- **Claude Code**：用 JSON merge 寫入 `~/.claude/settings.json`（預設）或 `<proj>/.claude/settings.json`。只新增帶有識別標記的 entry，command 用**絕對路徑**，不要依賴 PATH。matcher 用 `Bash|WebFetch|Write|Edit|mcp__(?!paste-warden).*`（不支援 lookahead 的話，就在 hook 內排除）。同時安裝 `UserPromptSubmit`。寫入前先備份成 `settings.json.pw-bak`，並保留原本的格式和其他 hook。
- **opencode**：寫入 `~/.config/opencode/plugins/paste-warden.ts`，內容是一個薄殼，負責呼叫 `paste-warden hook opencode`。檔案開頭加上版本標記；偵測 `opencode --version` 小於 2 時直接拒絕，或改裝 V1 版本。
- 安裝後自我測試：拿一筆無害的測試輸入跑 `paste-warden hook <agent> --self-test`，確認輸出格式正確。
- `paste-warden hook uninstall <agent>`：只移除有標記的 entry 或檔案；`paste-warden hook status`：列出已安裝的位置，並警告 `disableAllHooks` 是否開啟。
- hook 內部要 catch 全部錯誤、設好讀取上限，並且 fail-closed（Claude Code 用 exit 2，opencode 用 throw）。reason 只放訊息 ID 翻譯後的文字和遮罩過的片段，**絕對不放原文**。語言跟隨 `LANG`；兩種語言都輸出也可以，因為模型都看得懂。
- MCP 不自動安裝（roadmap §10）。`paste-warden mcp print-config <agent>` 只印出要貼的設定片段。

## 待決問題

- 擋下時要給模型什麼指示才能降低「換個寫法再試」的機率？要不要在 reason 裡寫明「再試也會被擋，請停止並詢問使用者」？
- hook 要不要在 `ask` 的情況下使用（中風險時交給使用者決定，而不是直接 deny）？opencode 有沒有對應的 ask 機制？
- 要不要支援 Claude Code 的 `PostToolUse`，用來檢查工具輸出（例如 WebFetch 抓回來的網頁裡的 ClickFix 指令）？
- opencode 在 Windows 的設定路徑，以及 `.ts` plugin 在 Windows 上的 spawn 行為，都還沒驗證。
- 其他 agent（Cursor、Codex CLI、Gemini CLI）的 hook 合約要排進哪個 Phase？
