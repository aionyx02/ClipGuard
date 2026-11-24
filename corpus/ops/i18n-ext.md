# i18n（瀏覽器插件）

## `i18n.display_label`

舊版插件 `displayLabel(finding)`：偵測器回傳的 `label` 不翻譯（規則檔裡的 zh-TW 名稱），顯示時才依**規則 id** 換成目前語言的規則名稱；沒有這條規則的翻譯時，用偵測器給的 `label`。新版對應「規則 id → Fluent 訊息」的查表，查不到時退回規則檔的 label。

- `args`：
  - `locale`：`en` | `zh-TW`
  - `rule`：規則 id（例如 `private-key-pem`、`tw-mobile`、`credit-card`）
  - `label`：偵測器回傳的 label（查不到翻譯時的退回值）
- `expect`：
  - `text`：顯示的名稱（完全相等）

`i18n.localized` 也可以包 `pastejack.compare`（`args.op = "pastejack.compare"`，`args.args` = 它的 `selection`／`written`）：`reasons_include`、`first_reason` 以 `locale` 的語言完全比對。
