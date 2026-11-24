# secret（遮罩）

## `secret.mask_value`

舊版 `SecretMasker.Mask(value, keepStart, keepEnd)`：把單一字串遮成 `A12****789` 這種形式。

- `input`：Text，要遮罩的值（可以是空字串）
- `args`：
  - `keep_start`：開頭保留幾個字元；沒寫 = 3
  - `keep_end`：結尾保留幾個字元；沒寫 = 3
- 行為（舊版）：保留字元數會縮減到「至少 4 個字元被遮住」（先縮尾端）；星號最多 8 個；空字串回傳空字串
- `expect`：
  - `output`：遮罩結果（Text），完全相等
  - `output_not_contain`：結果不能包含這些字串（Text 陣列）
  - `star_count_min`：結果裡 `*` 的數量至少這麼多
  - `output_ne_input`：`true` 表示結果不能等於輸入

## `secret.mask_text`

舊版 `PasteGuard.MaskText(text, SecretDetector.Find(text, packs))`：「貼遮罩版」，把整段文字裡偵測到的機密依原文位置換成遮罩字串。

- `input`：Text，原文
- `args`：
  - `packs`：個資包陣列；沒寫 = `["universal", "tw"]`
- 行為（舊版）：依位置由前往後替換，重疊或越界的結果略過；PEM 標頭會一路遮到 `-----END ` 行（細節見 `PasteGuard.MaskText`）
- `expect`：
  - `output`：替換後的完整文字（Text），完全相等
