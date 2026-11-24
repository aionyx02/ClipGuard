# locales

[Fluent](https://projectfluent.org/) 字串檔，Rust（`fluent-bundle`）與 JS（`@fluent/bundle`）共用同一份。

- `zh-TW/`、`en/` 底下的檔名與訊息 ID 必須一一對應（Phase 1 起由測試檢查）。
- 訊息 ID 用 kebab-case，依來源加前綴：`cmd-`（指令偵測）、`secret-`、`hidden-`、`wallet-`、`entry-`、`paste-`、`ui-`。
- Core 只回傳訊息 ID 和參數，翻譯一律在 UI 端。
