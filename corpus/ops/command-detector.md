# command（detector / normalizer 補充）

`command.explain` 的定義見 `command-explain.md`。

## `command.normalize_length`

舊版 `CommandNormalizer.Normalize(text)` 的輸出長度上限（變數代入不能無限膨脹）。正規化本身同 `command.normalize`。

- `input`：Text
- `args`：無
- `expect`：
  - `len_utf16_lt`：整數；正規化結果的長度（UTF-16 code unit）要**小於**這個值
