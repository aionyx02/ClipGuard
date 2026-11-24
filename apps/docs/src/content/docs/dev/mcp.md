---
title: MCP server
description: paste-warden mcp：給 AI agent 用的唯讀分析工具。
sidebar:
  order: 20
---

`paste-warden mcp` 是 stdio MCP server，讓 agent 可以分析一段文字、看解混淆過程或取得遮罩版。它**不是防護**，防護靠 [agent hook](../agent-hooks/)。

完整說明：[`docs/integrations/mcp.md`](https://github.com/aionyx02/paste-warden/blob/dev/docs/integrations/mcp.md)

## 工具（guard profile，全部唯讀）

| 工具 | 回傳 |
|---|---|
| `analyze { text, locale? }` | 判定報告（Report JSON） |
| `deobfuscate_trace { text, locale? }` | 每一層解混淆的結果（遮罩後） |
| `scan_secrets { text, packs? }` | 機密的種類與遮罩 |
| `mask { text }` | 遮罩後的文字 |

## 刻意不做的事

- **沒有讀取剪貼簿的工具**：否則被 prompt injection 的 agent 可以用它偷走你的剪貼簿。
- 只用 stdio，不開網路埠。
- 輸出一律遮罩，不含機密原文。

規格：[Phase 2 §2.5](https://github.com/aionyx02/paste-warden/blob/dev/docs/plan/phase-2.md)
