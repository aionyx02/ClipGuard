# guard

## `guard.run`

舊版 `ClipboardGuardState`：剪貼簿防護的狀態機（判定 → 隔離 → 還原，§2）。每個案例從一個**全新**的狀態開始，依序套用 `events`。

- `input` / `args`：無
- `events`：陣列，每個事件有 `t_ms`（遞增；這個狀態機不看時間，只用來排序）和**下面其中一種**動作，可再帶 `expect`（套用這個事件之後檢查）：
  - `"clipboard": Text` ：剪貼簿通知，讀到這段文字（App 已截到 `limits.MAX_ANALYZED_CHARS`）。= `OnClipboardText(text, readFull)`
  - `"clipboard": null` ：剪貼簿通知，但沒有文字（空的、圖片、檔案，**也包括我們自己清空剪貼簿引發的通知**）。
  - `"read_full": Text | null` ：只能和 `"clipboard": Text` 一起出現。表示這次通知有「讀取完整內容」的方法，呼叫時回傳這個值（`null` = 讀不到）。沒寫 = 沒有這個方法（等同讀不到）。
  - `"restore": "begin"` ：使用者按「還原」。= `BeginRestore()`：回傳要寫回剪貼簿的內容（沒有隔離內容時為 `null`），並**先**把它標成可信。
  - `"restore": "end_ok"` / `"restore": "end_failed"` ：寫回剪貼簿成功／失敗。= `EndRestore(succeeded)`。
- 狀態機規則（舊版行為，Rust 版要一樣）：
  - `clipboard: null`：若 `quarantine_active` 為真，什麼都不變（世代也不變）；否則 `level = none`、`verdict = none`、世代 +1。動作一律 `none`。
  - `clipboard: Text`：世代 +1、`quarantine_active = false`。若文字**完全等於**可信文字：`level = suspicious`、動作 `none`、不重新分析、不讀完整內容。否則清掉可信文字，用 `command.analyze` 判定：
    - `malicious` → `quarantined = read_full() ?? text`（**只有這時**才呼叫 `read_full`）、可信比對用的 key = `text`（截斷後的前綴）、`quarantine_active = true`、`level = none`、動作 `quarantine`
    - `suspicious` → `level = suspicious`、動作 `warn_suspicious`（`quarantined` 不變）
    - `none` → `level = none`、動作 `none`
  - `restore: begin`：沒有隔離內容 → 回傳 `null`；否則可信文字 = 隔離時的 key（前綴），回傳完整的隔離內容。
  - `restore: end_ok` → `quarantined = null`、`quarantine_active = false`（可信文字保留，直到下一個不同的文字出現）；`end_failed` → 清掉可信文字，隔離內容保留。
  - 用「內容比對」而不是「略過下一次通知」：還原引發的通知可能來 0 次或很多次。
- `expect`（每個事件；全部選填）：
  - `action`：`none` | `warn_suspicious` | `quarantine`（只對 `clipboard` 事件）
  - `restored`：Text | `null`，`restore: begin` 的回傳值
  - `read_full_called`：bool，這次事件有沒有呼叫 `read_full`
  - `quarantined`：Text | `null`，事件後的隔離內容
  - `quarantine_active`：bool，「剛攔截、使用者還沒複製別的」
  - `level`：`none` | `suspicious` | `malicious`，目前剪貼簿內容給執行入口用的判定（`ClipboardGuardState.Level`）
  - `verdict_level`：`none` | `suspicious` | `malicious`，最近一次分析的判定（`LastVerdict.Level`）
  - `generation`：`"increased"` | `"unchanged"`，和這個事件之前比
