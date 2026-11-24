---
title: 開發者概觀
description: PasteWarden 的架構、repo 結構與文件網站的建置方式。
sidebar:
  order: 1
---

PasteWarden 以 Rust 核心為中心，各平台只是外殼：

```
crates/core（偵測引擎，純邏輯、可編譯成 wasm32）
  ├── crates/cli          paste-warden 執行檔：scan、hook、MCP server
  ├── crates/wasm ──▶ packages/core-js（@paste-warden/core）
  │                     ├── apps/extension   WXT：Chrome / Edge / Firefox
  │                     ├── apps/userscript  單一 paste-warden.user.js
  │                     └── apps/web         試玩網頁
  └── crates/py           Python 綁定（紅隊評測）
```

前端共用兩個套件：

- `packages/ui`：React + Tailwind 元件（VerdictCard、OnionTrace、SecretList、MaskPreview）與 ThemeProvider、LocaleProvider。
- `packages/overlay`：注入網頁的警告層，原生 DOM + closed Shadow DOM，gzip 後不到 15 KB。

UI 字串放在 `locales/{zh-TW,en}/ui*.ftl`（Fluent），Rust 與 JS 共用同一份。

## 規格與決策

| 文件 | 內容 |
|---|---|
| [威脅模型](generated/threat-model/) | 保護的資產、信任邊界、威脅與對策（建置時從 `docs/THREAT_MODEL.md` 複製） |
| [偵測規格](generated/detection-rules/) | 偵測原則 P1–P7、各類訊號、分數公式（建置時從 `docs/spec/detection-rules.md` 複製） |
| [roadmap](https://github.com/aionyx02/paste-warden/blob/dev/docs/plan/roadmap.md) | 架構與已定案的決策 |

## 文件網站

這個網站是 `apps/docs`（Starlight）。威脅模型和偵測規格在建置時由 `scripts/sync-docs.mjs` 從 `docs/` 複製過來，請直接修改原始檔。

```sh
pnpm --filter @paste-warden/docs dev     # 本機預覽 http://localhost:4321/docs/
pnpm --filter @paste-warden/docs build   # 輸出到 apps/docs/dist
```
