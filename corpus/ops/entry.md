# entry

執行入口（Win+R、檔案總管、檔案對話框、終端機）的判斷與警告（§4）。視窗資訊是純資料：`class`（視窗 class）、`title`（視窗標題）、`process`（行程名稱，可帶 `.exe`）。三者都可以是 `null`（等同空字串）。

## `entry.classify`

舊版 `ExecutionEntryGuard.Classify(class, title, process)`。

- `args`：`class`、`title`、`process`（string | null）
- 規則：`title`、`process` 先 trim；`process` 去掉結尾 `.exe`（不分大小寫）；`explorer` 比對不分大小寫。
  - `class == "#32770"`（精確比對）：`process` 是 explorer 且標題（不分大小寫）是 `執行`/`Run`/`运行` → `run_dialog`；標題是 `開啟`/`開啟檔案`/`上傳檔案`/`選擇要上傳的檔案`/`Open`/`Open File`/`File Upload`/`Choose File to Upload`/`打开` → `file_dialog`；否則 `none`。
  - `process` 是 explorer 且 `class` 是 `CabinetWClass` 或 `ExploreWClass` → `file_explorer`
  - `class`（不分大小寫）是 `CASCADIA_HOSTING_WINDOW_CLASS`/`ConsoleWindowClass`/`org.wezfurlong.wezterm`/`mintty`，或 `process` 是 `WindowsTerminal`/`wezterm-gui`/`alacritty`/`mintty`/`powershell_ise` → `terminal`
  - 其他 → `none`
  - （這些清單在 Rust 版應放進 `rules/`；macOS / Linux 的對應入口另外加，不影響這些案例。）
- `expect`：
  - `entry`：`none` | `run_dialog` | `file_explorer` | `file_dialog` | `terminal`

## `entry.decide`

舊版 `ExecutionEntryGuard.Decide(class, title, process, level, quarantined)`：前景視窗是執行入口時，依剪貼簿狀態決定要不要警告。

- `args`：`class`、`title`、`process`（同 `entry.classify`）；`level`：`none` | `suspicious` | `malicious`（目前剪貼簿判定，即 `guard.run` 的 `level`）；`quarantined`：bool（即 `guard.run` 的 `quarantine_active`）
- 規則：不是入口 → 不警告。`quarantined` 或 `level == malicious` → `malicious` 警告；標題「小心！你剛打開了{入口}」，內文第一行是「剛才攔截的指令已從剪貼簿清空。」（quarantined）或「剪貼簿裡有惡意指令。」，第二行是勸告（提到「詐騙」）。`level == suspicious` → `suspicious` 警告（標題「你打開了{入口}，剪貼簿裡有會執行程式的指令」）。其他 → 不警告。
- `expect`（訊息以 zh-TW 比對，除非經由 `i18n.localized` 指定語系）：
  - `warn`：bool，有沒有警告（舊版回傳 null = `false`）
  - `entry`：同 `entry.classify`
  - `level`：`suspicious` | `malicious`，警告等級
  - `title`：完整標題；`title_contain`：子字串陣列
  - `body_contain`：子字串陣列；`body_starts_with`：字串
  - `title_max_utf16` / `body_max_utf16`：標題／內文（兩行以 `\n` 連接）的長度上限（UTF-16 code unit；舊版是系統匣通知的 63 / 255）

## `entry.gate`

舊版 `EntryWarningGate`：同一份剪貼簿內容，對同一個視窗只警告一次。每個案例從新的 gate 開始。

- `events`：`{"t_ms": n, "window": 整數視窗代號, "generation": 整數剪貼簿世代, "expect": {...}}`
- 規則：`generation` 和上一次不同 → 清空已警告集合並記住新世代；然後若 `window` 還沒警告過 → 記下並回傳 `true`，否則 `false`。初始世代是「沒有」（任何值都算不同）。
- `expect`：
  - `warn`：bool，`TryEnter` 的回傳值
