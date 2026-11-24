# hidden（1b）

1b 沒有新增 op 或 expect 欄位：`corpus/cases/hidden-1b-*.jsonl` 用的是既有的 `hidden.analyze`（`ops/hidden.md`）。
這裡記錄 1b 改變的**判斷規則**（細節見 `docs/spec/detection-rules.md` §6.1），供寫案例時對照。

## hidden.analyze（1b 補充） 的 1b 規則變更

- **資料搬到 `rules/hidden/`**：shell 指令清單（`shell-commands.json`）、同形字（`homoglyphs.json`，每個文字系統一組，
  訊息的 `script` 參數取自資料）、標準區旗 TAG 序列（`tag-sequences.json`）、ZWNJ／ZWJ 的例外（`joiners.json`）。行為不變。
- **「這一行像不像指令」**：改回舊版的 `command::analyze(line).level != none`，再加上 shell 指令清單。1a 的替代品
  （插件的指令訊號）拿掉了；指令偵測認得、清單裡沒有的程式（例如 `wscript`、`explorer` 開 WebDAV 路徑）現在也算指令。
- **ZWJ 接在 virama 後面**：「同一個印度系文字區塊的字母 + 該區塊的 virama + ZWJ」放行，ZWJ 後面可以是空白、標點、
  同一區塊的字元或文字結尾（馬拉雅拉姆文 chillu `ന്‍`、天城文半字形）。後面接英文字母、數字或其他看不見的字元照算；
  ZWNJ 不適用這條（仍要夾在兩個複雜文字的字母之間）。
- **新加入的看不見字元**（算在「其他看不見的字元」，理由列出 code point）：
  - U+034F（CGJ）：後面不是組合符號時；
  - U+17B4／U+17B5（高棉文固有母音）：不是夾在兩個高棉文字元（U+1780–17FF）之間時；
  - U+2061–2064（看不見的數學運算子）：前後緊鄰零寬字元或另一個數學運算子（U+200B–200D、U+2060–2064、U+FEFF），
    或所在那一行像指令或網址（同 soft hyphen 的判斷，共用每行一次、最多 256 行的上限）。
