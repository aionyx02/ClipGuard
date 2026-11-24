# throttle

## `throttle.run`

舊版 `NotificationThrottle`：通知節流（§2.1、P2）。時間由事件的 `t_ms` 注入（取代 `TimeProvider`）。每個案例從新的節流器開始。

- `args`：
  - `min_interval_ms`：兩則通知的最小間隔，沒寫 = `1000`
  - `visible_for_ms`：通知視為還在畫面上的時間，沒寫 = `6000`
- `events`：每個事件有 `t_ms`（目前時間，不遞減）和下面其中一種動作，可帶 `expect`：
  - `"submit": {"level": "warning" | "error", "title": string, "restorable": bool（沒寫 = false）}` ：送出通知。`restorable: true` 是「已攔截，點擊還原」那一則。
  - `"flush": true` ：計時器到了。
  - `"clipboard_changed": true` ：剪貼簿換了內容。
- 規則（舊版行為）：
  - 狀態：`last_shown_at`（沒有）、`last_shown_restorable`、`pending`（最多一則）。
  - `due(n)`：沒顯示過 → 立刻；否則 `last_shown_at + min_interval`；若上一則是 restorable 而 `n` 是 warning → `last_shown_at + visible_for`。
  - `show_now(n)`：`replace_visible = 有 last_shown_at 且 now - last_shown_at < visible_for`；記下 `last_shown_at = now`、`last_shown_restorable = n.restorable`、清空 `pending`。
  - `submit`：restorable → 一律 `show_now`。否則：`pending` 為空或 `pending.level <= n.level`（warning < error）時 `pending = n`（等待中的 error 不被 warning 蓋掉）；`due(pending) <= now` → `show_now(pending)`，否則不顯示、`retry_in = due - now`。
  - `flush`：沒有 pending → 什麼都不做（不顯示、`replace_visible = false`、`retry_in = null`）；否則同 submit 的後半段。
  - `clipboard_changed`：清空 `pending`（restorable 從不進 pending，所以不受影響）。
- `expect`：
  - `show`：string | `null`，這次要顯示的通知標題（`null` = 不顯示）
  - `shown`：bool，這次有沒有要顯示的通知（舊測試只檢查 not null 時用）
  - `replace_visible`：bool，要先撤掉畫面上的上一則
  - `retry_in_ms`：整數 | `null`，多久後要再 flush
  - `pending`：string | `null`，事件後等待中的通知標題
