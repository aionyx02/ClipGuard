# wallet

錢包地址辨識與掉包偵測（§6.2）。幣別列舉：`bitcoin` | `ethereum` | `tron`（`ethereum` 包含共用 0x 地址的 EVM 鏈）。

Text 欄位**省略或 `null`** = 舊版傳 `null`（非文字內容）。結果和空字串相同（`wallet.parse` 無效、`wallet.find_all` 沒有結果）；
`wallet.swap` 的 `copy: null` 是「剪貼簿變成非文字內容」。

## `wallet.parse`

舊版 `WalletAddress.TryParse(text, out currency, out normalized)`：**整段**（去掉頭尾空白後）是不是一個有效地址。

- `input`：Text
- 規則：長度 26–90；ETH = `0x`/`0X` + 40 hex（不驗 EIP-55）；BTC bech32 / bech32m（`bc1`，v0 程式 20 或 32 bytes、v1 32 bytes，
  不能大小寫混用）；BTC `1…`（Base58Check 版本 0x00）/ `3…`（0x05）；TRON `T…`（Base58Check 版本 0x41）。
- `expect`：
  - `valid`：`true` | `false`
  - `currency`：幣別（`valid: true` 時）
  - `normalized`：比較是否同一地址用的正規化字串（ETH、bech32 轉小寫；Base58 保持原樣）

## `wallet.find_all`

舊版 `WalletAddress.FindAll(text)`：找出文字裡所有通過驗證的地址，依出現順序。

- `input`：Text
- 規則：候選 = 一段連續 ASCII 英數字（前後不能緊鄰 ASCII 英數字），長度 26–90，整段拿去 `wallet.parse`；
  候選起點只掃前 `MAX_SCAN_LENGTH = 100000` 個 UTF-16 字，最多驗證 `MAX_CANDIDATES = 256` 個候選（長度不符的不算候選）。
- `expect`：
  - `count`：結果數量（`0` = 舊測試的 `Assert.Empty`）
  - `matches`：**完整**結果（數量、順序一樣），每筆只寫有檢查的欄位：
    `currency`、`text`（原文在 `span` 位置的子字串）、`span_utf16`、`normalized`

## `wallet.swap`

舊版 `WalletSwapDetector.Observe(text, userIdle)`：clipper 惡意程式的地址掉包偵測。時間由案例注入（舊版的 `FakeClock`），
**每個案例用一個新的偵測器**。

- `events`：依序處理的剪貼簿變動，每一筆：
  - `t_ms`：這次變動的時間（整數毫秒，任意原點；可以比前一筆小，代表時鐘倒退）
  - `copy`：剪貼簿的新內容（Text；`null` = 非文字內容）
  - `user_idle_ms`：（選填）現在距離使用者最後一次鍵盤或滑鼠輸入多久（舊版 `GetLastInputInfo`）。**省略 = 不知道輸入狀態**（舊版傳 `null`）
  - `expect`：（選填）這一筆 `Observe` 的回傳值；沒寫就不檢查
- 案例層級的 `expect` 固定是 `{}`，檢查都寫在各事件裡。
- 事件的 `expect`：
  - `swap`：`false` = 沒有偵測到掉包（回傳 null）；`true` = 有偵測到（只檢查非 null）；
    物件 = 有偵測到，而且符合下列有寫的欄位：
    - `currency`：原本地址的幣別；`replacement_currency`：換上的地址的幣別
    - `original` / `replacement`：被換掉的那個地址、換上的地址（原文，Text）。只給測試用，通知不顯示（P4）
    - `elapsed_ms`：距離記住的那份內容的時間
    - `signal`：`fast_replacement` | `same_surrounding_text` | `no_user_input`

狀態機（常數：`FAST_WINDOW = 1000`、`WINDOW = 3000`、`COPY_INPUT_GRACE = 500`，單位 ms）：

1. 用 `wallet.find_all` 找出 `copy` 裡的地址。**沒有地址**（含 `null`、空字串）→ 回傳無，**記憶不變**（A → `x` → B 仍拿 A 比）。
2. 有地址：做出這份內容的快照 `cur`：
   - `addresses`：每個地址的 `normalized`、幣別、原文；
   - `template`：把每個地址換成 U+FFFC 後的整段文字，再去掉頭尾空白（舊版只存它的 SHA-256；比較結果等同字串相等）；
   - `has_context`：`template` 裡有 U+FFFC 和空白以外的字元；
   - `at = t_ms`。
   取出舊的記憶 `last`，然後**無論結果如何**都把記憶換成 `cur`。
3. 沒有 `last` → 回傳無。
4. `elapsed = cur.at - last.at`。`elapsed < 0` 或 `elapsed > WINDOW` → 回傳無。
5. `template` 不同，或地址數量不同 → 回傳無。
6. 依序找第一個 `normalized` 不同的位置 `i`；都一樣 → 回傳無（只差大小寫的 ETH / bech32 是同一地址）。
7. 訊號，依序判斷：
   - `has_context` → `same_surrounding_text`（WINDOW 內都警告，不看輸入狀態）；
   - 否則 `elapsed <= FAST_WINDOW` → `fast_replacement`；
   - 否則 `user_idle_ms` 有值，而且「最後一次輸入的時間」`t_ms - user_idle_ms <= last.at + COPY_INPUT_GRACE` → `no_user_input`；
   - 否則回傳無。
8. 回傳 `{currency: last 第 i 個的幣別, replacement_currency: cur 第 i 個的幣別, original: last 第 i 個的原文,
   replacement: cur 第 i 個的原文, elapsed_ms: elapsed, signal}`。

邊界：`elapsed == 1000` 仍算 fast；`elapsed == 3000` 仍在 WINDOW 內；輸入剛好在 `last.at + 500` 仍算「沒有輸入」。
