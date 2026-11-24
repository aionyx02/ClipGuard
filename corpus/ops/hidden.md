# hidden

## `hidden.analyze`

舊版 `HiddenCharDetector.Analyze(text)`：看不見的字元、同形字、結尾換行（§6.1）。

- `input`：Text
- `expect`：
  - `level`：`none` | `suspicious`
  - `reasons_contain` / `reasons_not_contain`：同 `command.analyze`
  - `reasons_empty`：`true`
