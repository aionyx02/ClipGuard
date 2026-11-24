---
title: Developer overview
description: PasteWarden's architecture, repository layout, and how this site is built.
sidebar:
  order: 1
---

PasteWarden is built around a Rust core; each platform is a thin shell:

```
crates/core (detection engine: pure logic, compiles to wasm32)
  ├── crates/cli          the paste-warden binary: scan, hook, MCP server
  ├── crates/wasm ──▶ packages/core-js (@paste-warden/core)
  │                     ├── apps/extension   WXT: Chrome / Edge / Firefox
  │                     ├── apps/userscript  a single paste-warden.user.js
  │                     └── apps/web         the playground
  └── crates/py           Python bindings (red-team evaluation)
```

Two shared front-end packages:

- `packages/ui`: React + Tailwind components (VerdictCard, OnionTrace, SecretList, MaskPreview) plus ThemeProvider and LocaleProvider.
- `packages/overlay`: the in-page warning layer, plain DOM in a closed Shadow DOM, under 15 KB gzip.

UI strings live in `locales/{zh-TW,en}/ui*.ftl` (Fluent), shared by Rust and JS.

## Specs and decisions

| Document | Contents |
|---|---|
| [Threat model](generated/threat-model/) | Assets, trust boundaries, threats and mitigations (copied from `docs/THREAT_MODEL.md` at build time) |
| [Detection spec](generated/detection-rules/) | Principles P1–P7, signal classes, the score formula (copied from `docs/spec/detection-rules.md`) |
| [Roadmap](https://github.com/aionyx02/paste-warden/blob/dev/docs/plan/roadmap.md) | Architecture and settled decisions |

The specs are written in Traditional Chinese; the English site shows the same text.

## This site

This site is `apps/docs` (Starlight). The threat model and detection spec are copied from `docs/` at build time by `scripts/sync-docs.mjs`; edit the originals.

```sh
pnpm --filter @paste-warden/docs dev     # preview at http://localhost:4321/docs/
pnpm --filter @paste-warden/docs build   # output in apps/docs/dist
```
