---
title: Privacy promise
description: What PasteWarden never does, and what each extension permission is for.
sidebar:
  order: 20
---

PasteWarden handles the most sensitive things on your clipboard, so these rules are built into the architecture and can't be switched off:

- **Everything is judged locally.** The engine is WebAssembly running in your browser; clipboard content is never sent to a server.
- **The original text is never stored.** Clipboard content is not written to files, logs, error messages or notifications.
- **Secrets are always masked.** Any secret shown on screen or in history is masked. Secrets you register yourself are stored only as HMAC-SHA256 hashes.
- **History is a summary.** The popup's "recent blocks" keeps the domain, time, kind and masked string only.
- **No telemetry by default.** No usage statistics, no crash reports.
- **AI features are off by default.** LLM explanations must be turned on and configured by you. When personal data or keys are detected, the program refuses to send the content to a cloud model. AI can only raise a risk level, never lower the local engine's verdict.

## Extension permissions

| Permission | Why |
|---|---|
| Access to all sites (`<all_urls>`) | Intercept clipboard writes and check pastes in every page and iframe. Nothing else on the page is read |
| `storage` | Your settings and the block summaries |
| `offscreen` (Chrome only) | Used only when the clipboard has to be overwritten |

PasteWarden does **not** ask for `tabs`, `history` or similar permissions and never reads your browsing history.

## Open source

All code, detection rules and the [threat model](../../dev/generated/threat-model/) are public on GitHub. Please check them.
