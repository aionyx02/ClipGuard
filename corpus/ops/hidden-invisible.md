# hidden（補充：理由細節）

## 補充慣例：省略 input（null）

舊版 `HiddenCharDetector.Analyze(string?)` 可以收 `null`（非文字內容）。案例裡**省略 `input`** 就代表舊測試傳 `null`；
預期結果和空字串 `""` 完全相同（`level: none`、沒有理由）。Rust 版的 API 不接受 null 時，runner 把它當成 `""` 跑。

## `hidden.reasons`

和 `hidden.analyze` 是**同一個呼叫**（舊版 `HiddenCharDetector.Analyze(text)`，§6.1），只是要比對理由的細節：
同一條理由要同時提到好幾件事（例如「TAG」和「5 個」），或某一類理由只能有一條。

- `input`：Text（省略 = null，見上）
- `expect`：
  - `level`：`none` | `suspicious`
  - `reasons_contain` / `reasons_not_contain`：同 `hidden.analyze`（每個字串各自比對，可以落在不同理由）
  - `reasons_any`：字串陣列的陣列。每一組都要有**某一條**理由同時包含該組的全部字串
    （舊測試 `Assert.Contains(v.Reasons, r => r.Contains("TAG") && r.Contains("5 個"))` → `[["TAG", "5 個"]]`）
  - `reasons_single`：物件 `{"contain": 字串, "all": [字串…], "none": [字串…]}`。包含 `contain` 的理由**剛好一條**
    （`Assert.Single`），而且那一條要包含 `all` 的每一個、不能包含 `none` 的任何一個

數量一律寫成 zh-TW 訊息裡的「`N 個`」（例如 `含 Unicode TAG 字元 5 個（…）`）。TAG 字元一個算一個（UTF-16 代理對算一個），
不解碼、理由裡不出現藏起來的內容；其他看不見的字元的理由列出最多三個不同的 code point（`U+XXXX`，用「、」分隔），不列原文。
