---
title: Agent hook
description: 用 paste-warden CLI 在 Claude Code 和 opencode 執行指令前強制檢查。
sidebar:
  order: 10
---

AI coding agent 可能被網頁內容（prompt injection）騙去執行指令或把機密送出去。PasteWarden 用 **hook** 在 agent 執行工具前強制檢查，這是真正的防護；[MCP server](../mcp/) 只負責分析和解釋，因為模型可以選擇不呼叫它。

完整說明（安裝、驗證、移除）：[`docs/integrations/agent-hooks.md`](https://github.com/aionyx02/paste-warden/blob/dev/docs/integrations/agent-hooks.md)

## 重點

- **Claude Code**：`PreToolUse` hook 檢查 Bash 指令、WebFetch 與 MCP 參數。判定為已隔離 → `deny`；請注意 → `ask`（讓你確認）；安全 → 不輸出，不會蓋掉你自己的權限規則。
- **對外請求帶有機密**（WebFetch 的網址、`curl -d`、MCP 參數）→ `deny`。
- **opencode**：產生 V2 plugin（`ctx.tool.hook("execute.before")`）。舊的 V1 寫法會靜默失效，不要使用。
- **Fail-closed**：Claude Code 的 hook 在程式崩潰、逾時或回傳非預期的 exit code 時會放行，所以 `paste-warden hook` 自己接住所有錯誤（包括 panic 與 2 秒逾時）並回傳 deny。
- `paste-warden hook install claude-code`（預設 `--scope user`，可加 `--dry-run` 先看差異）；`hook uninstall` 移除。

規格：[Phase 2 §2.4](https://github.com/aionyx02/paste-warden/blob/dev/docs/plan/phase-2.md)
