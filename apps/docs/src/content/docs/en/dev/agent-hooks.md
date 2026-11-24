---
title: Agent hooks
description: Use the paste-warden CLI to enforce checks before Claude Code and opencode run tools.
sidebar:
  order: 10
---

AI coding agents can be tricked by web content (prompt injection) into running commands or sending secrets out. PasteWarden enforces checks with **hooks** that run before the agent's tools. That is the real protection; the [MCP server](../mcp/) only analyses and explains, because a model can choose not to call it.

Full guide (install, verify, remove), in Traditional Chinese: [`docs/integrations/agent-hooks.md`](https://github.com/aionyx02/paste-warden/blob/dev/docs/integrations/agent-hooks.md)

## Key points

- **Claude Code**: a `PreToolUse` hook checks Bash commands, WebFetch and MCP arguments. Quarantine → `deny`; caution → `ask` (you confirm); safe → no output, so your own permission rules still apply.
- **Outgoing requests carrying secrets** (WebFetch URLs, `curl -d`, MCP arguments) → `deny`.
- **opencode**: a generated V2 plugin (`ctx.tool.hook("execute.before")`). The old V1 style fails silently; don't use it.
- **Fail-closed**: Claude Code lets a tool run when its hook crashes, times out or returns an unexpected exit code, so `paste-warden hook` catches every error itself (including panics and a 2-second timeout) and answers deny.
- `paste-warden hook install claude-code` (default `--scope user`; add `--dry-run` to see the diff first); `hook uninstall` removes it.

Spec: [Phase 2 §2.4](https://github.com/aionyx02/paste-warden/blob/dev/docs/plan/phase-2.md)
