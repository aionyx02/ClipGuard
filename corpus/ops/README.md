# ops：每個 op 的定義

- 每個 area 一個主檔 `<area>.md`；同一個 area 有多人同時新增 op 時，可以另開 `<area>-<主題>.md`（`xtask corpus lint` 會一起讀）。
- 每個 op 用一個標題 `## \`<op>\``，底下寫：`input`、`args`、`events` 的意思，以及 `expect` 可以有哪些欄位。
- **所有 expect 欄位都是選填**：只寫原測試有檢查的部分。比對時「沒寫的欄位不檢查」。

## 共用慣例

| 項目 | 寫法 |
|---|---|
| 列舉值 | snake_case：`none` / `suspicious` / `malicious`；`national_id`、`api_key`… |
| 個資包 | 小寫：`universal`、`tw`、`us`、`cn`、`hk`、`jp`、`kr`、`sg`。沒寫 `packs` 時 = 舊版的 `SecretPacks.Default`（`universal` + `tw`） |
| 時間 | 毫秒整數，欄位名稱以 `_ms` 結尾 |
| 位置 | `span_utf16: [index, length]`（UTF-16 code unit，指原文） |
| 舊版的中文訊息 | 只用來表達「訊息內容要提到什麼」：`*_contain: ["零寬字元"]` 是子字串比對（zh-TW）。Phase 1 會把它對應到訊息 ID 的 zh-TW 翻譯 |
| 訊息語言 | 舊測試在 zh-TW 文化下執行（`TestCulture`）；除非 op 另有 `locale` 參數，訊息一律以 zh-TW 比對 |
