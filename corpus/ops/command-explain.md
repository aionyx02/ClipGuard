# command：白話說明與官方安裝網站清單

## `command.explain`

舊版 `CommandExplainer.Explain(text)`：把指令翻成白話（§3.3）。內部先取前 4096 字、正規化（同 `command.normalize`），找 `-EncodedCommand` 並以 UTF-16LE 解碼，解碼內容一起分析。

- `input`：Text
- `args`：無
- `expect`：
  - `actions`：字串陣列，白話說明的**完整**清單（順序也要相同）
  - `actions_first`：字串，第一條白話說明（完全相等）
  - `actions_contain`：字串陣列，每一個都要**完全等於**某一條白話說明（舊測試用 `Assert.Contains(string, list)`，是元素相等，不是子字串）
  - `summary`：字串，所有說明以 zh-TW 分隔符 `；` 串起來的結果（完全相等）
  - `decoded`：字串或 `null`。解碼後的 `-EncodedCommand` 原文；`null` 表示沒有解碼內容（沒有編碼參數，或解不開）

## `command.explain_display`

舊版 `CommandExplanation.ToDisplayText(maxLength)`：給通知用的短文字。第一行 `白話：<summary>`；有解碼內容時第二行 `解碼：<解碼內容>`（連續空白與換行壓成一個空白、去頭尾空白）。總長超過上限時截成 `maxLength - 1` 個字再加 `…`。

- `input`：Text，先做 `command.explain`，再對結果產生顯示文字
- `args`：
  - `max_length`：整數，長度上限（UTF-16 code unit）
- `expect`：
  - `contains`：字串陣列，顯示文字要包含每一個（子字串）
  - `starts_with` / `ends_with`：字串
  - `max_len_utf16`：整數，顯示文字長度（UTF-16 code unit）≤ 此值

## `command.decode_encoded`

舊版 `CommandExplainer.DecodeEncodedCommand(text)`：找出 PowerShell `-EncodedCommand` 的參數（`-e`、`-en`…任意前綴，或別名 `-ec`；值是 ≥ 8 字的 Base64，可缺補位）並以 UTF-16LE 解碼。解不開、或解出來不像文字（含控制字元／替代字元，或可印 ASCII 不到一半）時為 null。**不**做正規化。

- `input`：Text
- `args`：無
- `expect`：
  - `output`：字串或 `null`，解碼結果；`null` 表示沒有可解碼內容

## `command.is_official_host`

舊版 `DownloadExecution.IsOfficialHost(host)`：主機名稱是否在官方安裝網站清單（§3.2，#20 F17）內。比對不分大小寫，清單內主機本身或其子網域才算；子字串、前綴、帶其他字元都不算。

- `input`：字串，主機名稱
- `args`：無
- `expect`：
  - `official`：`true` | `false`
