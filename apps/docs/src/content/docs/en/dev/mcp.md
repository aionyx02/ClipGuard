---
title: MCP server
description: paste-warden mcp, read-only analysis tools for AI agents.
sidebar:
  order: 20
---

`paste-warden mcp` is a stdio MCP server that lets an agent analyse text, inspect the deobfuscation steps or get a masked copy. It is **not** a protection layer; [agent hooks](../agent-hooks/) are.

Full guide, in Traditional Chinese: [`docs/integrations/mcp.md`](https://github.com/aionyx02/paste-warden/blob/dev/docs/integrations/mcp.md)

## Tools (guard profile, all read-only)

| Tool | Returns |
|---|---|
| `analyze { text, locale? }` | The verdict report (Report JSON) |
| `deobfuscate_trace { text, locale? }` | The result of each deobfuscation layer (masked) |
| `scan_secrets { text, packs? }` | Kinds and masks of detected secrets |
| `mask { text }` | The masked text |

## Deliberately missing

- **No clipboard-reading tool**: a prompt-injected agent could use it to steal your clipboard.
- stdio only, no network port.
- Output is always masked and never contains secret plaintext.

Spec: [Phase 2 §2.5](https://github.com/aionyx02/paste-warden/blob/dev/docs/plan/phase-2.md)
