# limits

## `limits.prefix`

舊版 `ClipboardLimits.Prefix(text)`：剪貼簿的讀取上限（§2.2）。App 只讀前 `MAX_ANALYZED_CHARS` 個 UTF-16 code unit 分析。

- 常數 `MAX_ANALYZED_CHARS = 1048576`（`1 << 20`，UTF-16 code unit）
- `input`：Text（完整剪貼簿文字）
- 規則：長度 ≤ 上限 → 原樣；否則截到上限，但如果第 `MAX_ANALYZED_CHARS` 個 code unit 是高代理（代理對的前半），整個代理對都不要（長度 = 上限 − 1）。
- `expect`：
  - `length_utf16`：結果長度
  - `unchanged`：`true` = 結果與輸入完全相同
  - `ends_with_high_surrogate`：bool，結果最後一個 code unit 是不是高代理
  - `analyze_level`：`none` | `suspicious` | `malicious`，對結果跑 `command.analyze` 的判定
