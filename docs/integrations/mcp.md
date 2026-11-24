# MCP server：讓 agent 查詢 PasteWarden 的分析結果

`paste-warden mcp` 是一個 stdio MCP server（`rmcp` 3.x），讓 AI agent 在執行來路不明的指令前先問 PasteWarden，或在分享文字前先遮罩機密。

它只負責**分析和解釋**，不是防護：模型可以選擇不呼叫它。要強制擋下危險指令，請安裝 hook（見 [`agent-hooks.md`](agent-hooks.md)）。

## 安全設計

- 只用 stdio，不開任何網路埠；stdout 只放協定訊息，不寫 log。
- 所有工具都是唯讀的（`readOnlyHint: true`、`openWorldHint: false`），文字由參數傳入。
- **沒有讀取剪貼簿的工具**（THREAT_MODEL T9）：否則被 prompt injection 的 agent 可以用它偷走剪貼簿內容。
- 輸出一律遮罩：機密只回傳種類、規則、遮罩後的值和位置；解混淆的預覽也是遮罩後的。測試會在輸入裡埋一把假 API key 和一個身分證字號，確認四個工具的輸出都不含原文（`crates/cli/src/mcp.rs`、`crates/cli/tests/mcp.rs`）。
- 輸入上限 1 Mi 字元（1,048,576），超過回傳工具錯誤（`isError: true`），錯誤訊息不含輸入。
- 工具描述寫死在程式裡。
- MCP server 不會自動安裝（roadmap §10），要自己加到 agent 的設定。

## 工具（`--profile guard`，預設）

| 工具 | 參數 | 回傳（`structuredContent`） |
|---|---|---|
| `analyze` | `text`、`locale?`（`zh-TW` \| `en`） | Phase 2 §2.2 的 Report JSON |
| `deobfuscate_trace` | `text`、`locale?` | `{ trace, output_preview, capped }`：每一層解混淆步驟、遮罩後的還原結果（最多 2000 字）、是否碰到安全上限 |
| `scan_secrets` | `text`、`packs?`（如 `["tw","us"]`）、`locale?` | `{ secrets: [...] }`：種類、規則 ID、翻譯後的名稱、遮罩值、UTF-16 位置 |
| `mask` | `text` | `{ masked }`：遮罩後的文字 |

`locale` 沒給時用 server 啟動時的語言（`--locale`，或 `LC_ALL` / `LC_MESSAGES` / `LANG`）。每個工具也會附一份文字版的 JSON，給不支援 `structuredContent` 的 client。

`--profile redteam`（`validate_syntax`、`run_benchmark`）會在 Phase 5 加入，現在指定會回錯誤。

## 設定

印出要貼的設定片段（含執行檔的絕對路徑）：

```sh
paste-warden mcp --print-config claude-code
paste-warden mcp --print-config opencode
```

**Claude Code**：寫進專案的 `.mcp.json`，或單次使用：

```sh
claude --mcp-config mcp.json --allowedTools mcp__paste-warden__analyze
```

```json
{ "mcpServers": { "paste-warden": { "command": "/abs/path/paste-warden", "args": ["mcp"] } } }
```

server 名稱請用 `paste-warden`：hook 的 matcher 和程式只認這個名稱，用來排除自家工具（不然請 agent 分析一段惡意樣本時，hook 會把 `analyze` 本身擋下）。

**opencode**（`opencode.json` 或 `.opencode/opencode.json`；V2 的 server 放在 `mcp.servers` 底下）：

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": { "servers": { "paste-warden": { "type": "local", "command": ["/abs/path/paste-warden", "mcp"] } } }
}
```

opencode 2.2.0 的 `opencode mcp list` 可能顯示「No MCP servers configured」，但實際執行時可以用（S7）。另外 opencode 的模型常透過 `execute` 程式碼工具呼叫 MCP，PasteWarden 的 opencode plugin 會檢查 `execute` 的程式碼；把惡意樣本寫在程式碼裡請 agent 分析時，外層的 `execute` 可能被擋下。

## 實測

Claude Code 2.1.331 用 `--strict-mcp-config --mcp-config` 載入，四個工具都實際呼叫成功（同時裝著 hook，沒有擋到自家工具）。指令和結果見 [`agent-hooks.md`](agent-hooks.md) 的「實測紀錄」c、d。
