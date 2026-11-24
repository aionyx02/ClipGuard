# pastejack

Pastejacking（docs/spec/detection-rules.md §7）：比對「使用者選取的文字」和「網頁實際寫進剪貼簿的文字」。舊版只在瀏覽器插件（`extension/lib/pastejack.js`）。

## `pastejack.compare`

舊版 `analyzeCopy({selection, written})`：判斷網頁寫入剪貼簿的內容是不是被偷換、偷加了東西。

- `args`：
  - `selection`：Text，copy 當下使用者選取的文字（`""` = 沒有選取，例如按網頁上的「複製」按鈕）
  - `written`：Text，網頁實際要寫進剪貼簿的文字
  - `locale`：`en` | `zh-TW`，說明文字的語言；沒寫 = `zh-TW`（通常改用 `i18n.localized` 包起來）
- 規則（舊版）：
  1. 兩邊先正規化：刪掉看不見的字元（見下）、`\r\n`／`\r` → `\n`、U+00A0／U+2007／U+202F／U+3000 → 空白、連續空白（含換行）壓成一個空白、去頭尾。
  2. `written` 正規化後是空的，而且原文沒有看不見的字元 → `empty`，不警告（網頁擋複製，不是 pastejacking）。
  3. `written` 的看不見字元**數量**比 `selection` 多 → 原因「看不見的字元」。不分字元種類、沒有例外規則（使用者自己選到的區旗、斷字點兩邊都有，會互相抵銷）。
  4. 指令訊號（`pastejack.command_signals`）只算 `written` 有、`selection` 沒有的 → 每個加一則「網頁加入的內容 + 訊號名稱」。另外 `written`（去頭尾後）有換行、`selection` 沒有，而且有新增的指令訊號 → 原因「加入換行」。
  5. 判定：`selection` 正規化後是空的 → `unselected`，有新增指令訊號或看不見字元才警告；兩邊相同 → `same`，有新增看不見字元才警告；`written` 包含 `selection` → `appended`，有任何原因才警告（新聞網站附加出處不警告）；其他 → `replaced`，一律警告，原因最前面加「寫入的內容和你選取的文字不同」。
- 看不見的字元：U+00AD、U+115F、U+1160、U+180E、U+200B–200F、U+202A–202E、U+2060–2064、U+2066–2069、U+3164、U+FEFF、U+FFA0、U+E0000–E007F（TAG）、U+E0100–E01EF（補充區變體選擇符）。一個 code point 算一個。
- 時間條件（插件的 `content.js`，目前沒有語料）：同步的 copy 事件直接比對；網頁之後非同步寫入（`navigator.clipboard.writeText`）時，只有在上次複製後 2 秒內、而且這段期間使用者沒有任何點擊或按鍵（複製本身的 Ctrl/⌘+C、X 不算）才拿上次的 `selection` 比對，否則當成 `selection = ""`。之後要加語料時用 `events`：`[{"t_ms": 0, "copy": {"selection": Text, "written": Text}}, {"t_ms": n, "input": true}, {"t_ms": n, "async_write": Text, "expect": {…}}]`。
- `expect`：
  - `verdict`：`empty` | `same` | `appended` | `replaced` | `unselected`
  - `warn`：bool
  - `reasons_contain`：字串陣列；每一個都要是**某一則**原因的子字串（zh-TW，或 `locale` 的語言）
  - `reasons_include`：字串陣列；每一個都要**完全等於**某一則原因
  - `first_reason`：第一則原因（完全相等）

## `pastejack.command_signals`

舊版 `commandSignals(text)`：桌面版指令偵測的精簡子集，只用來判斷網頁偷塞的內容像不像要你執行的指令。回傳命中的訊號名稱（目前語系）。

- `input`：Text
- 訊號（舊版）：`powershell`／`pwsh`（前面是開頭、空白或 `;&|("'`，後面接參數、引號、`#`、結尾或 `|;&`；不分大小寫）、`mshta`（同樣條件）、`cmd /c`／`cmd /k`、`curl`／`wget` 同一行接 `| sh`／`bash`／`zsh`、`iex`／`invoke-expression`、`certutil`／`bitsadmin`／`rundll32`／`regsvr32`／`msiexec`、`sudo <指令>`
- `expect`：
  - `any`：bool，有沒有命中任何訊號

## `pastejack.normalize`

舊版 `normalize(text)`：`pastejack.compare` 第 1 步的正規化。

- `input`：Text
- `expect`：`output`：Text，完全相等

## `pastejack.preview`

舊版 `preview(text, max = 160)`：警告視窗顯示用。看不見的字元（同 `pastejack.compare`）換成 `⟦U+XXXX⟧`（大寫 hex、至少 4 位，補充平面的字元用完整 code point，例如 `⟦U+E0041⟧`）；換完之後超過 `max` 個 UTF-16 code unit 就截斷並加 `…`。

- `input`：Text
- `args`：`max`：整數；沒寫 = 160
- `expect`：`output`：Text，完全相等
