# command

## `command.analyze`

舊版 `CommandDetector.Analyze(text)`：判斷文字是不是會執行程式的指令、有沒有詐騙特徵。

- `input`：Text
- `args`：無
- `expect`：
  - `level`：`none` | `suspicious` | `malicious`
  - `level_not`：`none` | `suspicious` | `malicious`（舊測試用 `Assert.NotEqual`）
  - `reasons_include`：字串陣列，每一個都要**完全等於**某一條理由（舊測試用 `Assert.Contains(string, Reasons)` 時）
  - `reasons_contain`：字串陣列，每一個都要是某一條理由的子字串（zh-TW）
  - `reasons_not_contain`：字串陣列，沒有任何理由包含它
  - `reasons_empty`：`true` 表示沒有任何理由

## `command.normalize`

舊版 `CommandNormalizer.Normalize(text)`：比對規則前的正規化（§3.0）。

- `input`：Text
- `expect`：
  - `output`：Text，正規化後的完整結果
  - `contains` / `not_contains`：字串（或 Text）陣列，結果要包含或不包含
