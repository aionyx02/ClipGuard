# command（1b）

Phase 1b 新增的 op（解混淆、情境加權）。`command.analyze` 本身的欄位不變，見 `command.md`；1b 的 `command.analyze` 案例（`corpus/cases/command-1b-*.jsonl`）沿用它。

## `command.deobfuscate`

`command::deobfuscate(text)`：一層一層剝開混淆（洋蔥 trace，`docs/spec/detection-rules.md` §3.5）。

- `input`：Text
- `args`：無
- `expect`：
  - `output`：Text，剝完的完整結果
  - `contains` / `not_contains`：Text 或 Text 陣列，結果要包含或不包含
  - `kinds`：字串陣列，出現過的步驟種類（依第一次出現的順序、不重複），要完全相同。種類名稱見 `StepKind::as_str`：`invisible`、`dash`、`caret`、`variable`、`quote`、`program_path`、`markdown`、`full_width`、`backtick`、`url_decode`、`hex_decode`、`char_code`、`concat`、`join`、`format`、`replace`、`string_method`、`ps_variable`、`unwrap`、`base64`、`encoded_command`、`cmd_substring`、`nested_variable`
  - `kinds_include` / `kinds_exclude`：字串陣列，每一個都要出現／都不能出現
  - `max_layer_le`：整數，所有步驟的 `layer` 都不超過它（0 = 正規化）
  - `output_len_le`：整數，結果的字數（char）不超過它
  - `capped`：`true` / `false`，是否碰到上限（層數以外的上限：膨脹倍數、總長、步驟數）
  - `messages_contain`：字串陣列，每一個都是某個步驟說明（zh-TW）的子字串
  - `previews_not_contain`：Text 陣列，沒有任何步驟的預覽包含它（例如機密原文）

## `command.analyze_in`

`command::analyze_in(text, &Context)`：判定、`risk_score`、trace、下載來源主機。判定一定等於 `command.analyze` 的結果（adapter 會檢查）。

- `input`：Text
- `args`：
  - `context`（選填）：`{ "source": "browser" | "terminal" | "ide" | "chat" | "password_manager" | "other" | "unknown", "platform": "windows" | "macos" | "linux" | "android" | "ios" | "web" | "unknown", "app": "…", "url": "…" }`，每個欄位都可以省略；整個省略 = `Context::default()`
- `expect`：
  - `level`、`level_not`、`reasons_include`、`reasons_contain`、`reasons_not_contain`、`reasons_empty`：同 `command.analyze`
  - `risk_score`：整數，完全相等
  - `risk_score_min` / `risk_score_max`：整數，下限／上限（含）
  - `trace_kinds`、`trace_kinds_include`、`trace_kinds_exclude`：同 `command.deobfuscate` 的 `kinds*`，看的是 `trace`
  - `trace_empty`：`true` 表示沒有任何步驟
  - `hosts`：字串陣列，完全相等（小寫、依出現順序）
  - `hosts_include`：字串陣列，每一個都要在 `hosts` 裡
