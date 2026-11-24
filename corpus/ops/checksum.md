# checksum

## `checksum.validate`

舊版 `Checksums.IsValid*` / `IsPlausible*`：單一號碼的檢查碼或格式驗證。輸入是**已經去掉空白、連字號**的號碼（跟舊版一樣，這個 op 不做正規化）。

- `input`：Text，要驗證的號碼
- `args`：
  - `scheme`：驗證方式，下列其中之一：

    | `scheme` | 舊版 | 說明 |
    |---|---|---|
    | `tw_id` | `IsValidTaiwanId` | 台灣身分證、新式居留證（第 2 碼 8/9）、舊式居留證（第 2 碼 A–D）。首字母不分大小寫 |
    | `tw_ubn` | `IsValidBusinessId` | 統一編號，2023 起「被 5 整除」規則（含第 7 碼為 7 的 +1 規則） |
    | `luhn` | `IsValidLuhn` | Luhn mod 10；長度 < 2 一律不合法 |
    | `iban` | `IsValidIban` | ISO 13616：國家在長度表內、長度相符、檢查碼 02–98、mod 97 = 1。只接受大寫 |
    | `cn_rid` | `IsValidChinaResidentId` | 中國居民身分證（GB 11643-1999），另外檢查出生日期是真的日期 |
    | `jp_my_number` | `IsValidMyNumber` | 日本個人番號（12 碼） |
    | `hk_id` | `IsValidHongKongId` | 香港身分證，1–2 個大寫字母 + 6 碼 + 檢查碼（0–9 或 A），不含括號 |
    | `sg_nric` | `IsValidSingaporeNric` | 新加坡 NRIC／FIN（S、T、F、G、M） |
    | `us_ssn` | `IsPlausibleUsSsn` | 美國 SSN（沒有檢查碼，只排除不會發的範圍），9 碼數字 |
    | `e164` | `IsPlausibleE164` | 國際電話「+」後面的數字：已分配國碼、8–15 碼、+1／+7 剛好 11 碼 |
- `expect`：
  - `valid`：`true` / `false`
