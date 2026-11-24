# secret

## `secret.find`

舊版 `SecretDetector.Find(text, packs)`：找出個資和 API key。

- `input`：Text
- `args`：
  - `packs`：個資包陣列；沒寫 = `["universal", "tw"]`
- `expect`：
  - `matches`：**完整**結果（數量、順序都要一樣）。每一筆只寫有檢查的欄位：
    `kind`、`label`、`masked`（Text）、`span_utf16`
  - `matches_include`：結果裡**至少**要有這幾筆（同樣每筆只寫有檢查的欄位）
  - `matches_exclude`：結果裡**不能**有符合這些條件的項目
  - `count`：結果數量
  - `kinds_include` / `kinds_exclude`：結果的 kind 要包含或不包含
  - `masked_not_contain`：所有 `masked` 都不能包含這些字串（Text）

`kind`：`national_id`、`resident_certificate`、`business_id`、`credit_card`、`mobile_phone`、`api_key`、`registered`、`phone_number`、`bank_account`
