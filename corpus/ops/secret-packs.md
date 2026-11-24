# secret：規則包、只看 API key、規則檔載入

## `secret.packs_country_of`

舊版 `SecretPacks.CountryOf(regionOrCulture)`：地區設定或語系名稱對應的國家包。

- `args`：
  - `region`：字串或 `null`。可以是地區代碼（`TW`，單獨兩個**大寫**字母才算地區）、語系名稱（`zh-TW`、`zh-Hant-HK`、`zh_CN`，`-` 和 `_` 都當分隔），或只有語言（`ja`、`ko`，只有語言幾乎只在一個國家用的才對應）。空字串、空白、`null` = 沒有對應
- `expect`：
  - `country`：小寫的國家包名稱（例如 `tw`），沒有對應的國家包時是 `null`

## `secret.packs_for_region`

舊版 `SecretPacks.ForRegion(regionOrCulture, extra, disabled)`：要開的包 = 通用包 + 地區對應的國家包 + `extra`，再拿掉 `disabled`。

- `args`：
  - `region`：同 `secret.packs_country_of`
  - `extra`：字串陣列，手動加的國家包（不分大小寫、可有前後空白；不認得的代碼直接忽略）。沒寫 = 空
  - `disabled`：字串陣列，手動關的國家包（規則同上）。沒寫 = 空
- `expect`：
  - `packs`：要開的包（小寫）。**集合**比對：順序不重要，但不能多也不能少

## `secret.packs_list`

規則檔裡有哪些包。沒有 `input`、`args`。

- `expect`：
  - `countries`：舊版 `SecretPacks.Countries`：所有國家包（不含 `universal`），小寫、依代碼排序（**順序要一樣**）
  - `default`：舊版 `SecretPacks.Default`：沒有指定時用的包（集合比對）

## `secret.api_keys`

舊測試的 `ApiKeys(text)`：`secret.find` 的結果只留 `kind == api_key` 的項目（其他種類不檢查）。

- `input`：Text
- `args`：
  - `packs`：同 `secret.find`；沒寫 = `["universal", "tw"]`
- `expect`：
  - `count`：API key 結果的數量
  - `matches`：**完整**的 API key 結果（數量、順序都要一樣），每一筆只寫有檢查的欄位：
    - `label`、`masked`、`span_utf16`：同 `secret.find`
    - `masked_contains`：字串，`masked` 要包含它
    - `masked_prefix`：字串，`masked` 要以它開頭
    - `span_len_min`：命中範圍（原文的 `span_utf16` 那一段）至少幾個 UTF-16 code unit
    - `masked_not_contain_span`：`true` = `masked` 不能包含命中範圍的原文
  - `masked_not_contain`：Text 陣列；所有 API key 結果的 `masked` 都不能包含這些字串
  - `mask_text_not_contain_span`：`true` = 用**全部**結果（所有種類、同一組 `packs`）遮罩整段輸入（舊版 `PasteGuard.MaskText(text, SecretDetector.Find(text))`，即「貼遮罩版」）之後，輸出不能包含 `matches` 裡任何一筆命中範圍的原文

## `secret.rules_load`

舊版 `SecretRules.Load(files)`：只載入 `args.files` 給的規則檔（**不含**內建的 `rules/*.json`），用來測規則檔格式驗證。

- `input`：Text，選填。有寫時，用載入後的**第一條規則**直接掃描這段文字（舊版 `rules[0].Scan(text, text)`：不做全形轉換、不分段、不經過 `secret.find` 的合併），數命中幾筆
- `args`：
  - `files`：陣列，每筆 `{"name": "<檔名>", "json": Text}`，依序載入
- `expect`：
  - `error`：`true` = 載入要失敗（舊版丟 `InvalidDataException`）；`false` = 要成功
  - `error_contains`：字串陣列，錯誤訊息要包含這些子字串（例如檔名）
  - `scan_count`：`input` 被第一條規則命中幾筆（隱含載入成功）
