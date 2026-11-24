# registered

使用者登記的機密（§5.1）：只存標籤、長度與 **HMAC-SHA256**，不存原文，**禁止**改用單純的 SHA-256。金鑰的產生與保存（舊版 DPAPI + `key.bin`，新版 OS keyring）是平台層的事（Phase 4），這裡由案例注入金鑰，所以 HMAC 值可以精確比對。

長度一律以 **UTF-16 code unit** 計算（和舊版一致；`🔑` 算 2）。

## `registered.run`

舊版 `RegisteredSecretStore`：登記、比對、移除。每個案例從一個空的 store 開始。

- 常數：`MIN_LENGTH = 6`、`MAX_LENGTH = 256`、`MAX_LABEL_LENGTH = 40`、`MAX_SCAN_LENGTH = 20000`
- `args`：`key_hex`：64 個 hex 字元（32 bytes 的 HMAC 金鑰）
- `events`：每個事件有 `t_ms`（只用來排序）和下面其中一種動作，可帶 `expect`：
  - `"add": {"label": string | null, "secret": Text}`，可加 `"as": "<名稱>"` 讓之後的 `remove` 指到這一筆
  - `"find": Text | null`
  - `"remove": "<名稱>" | null`（`null` = 一個從沒登記過的 id）
  - `"reopen": true`：模擬重新啟動（同一把金鑰、同樣的已存項目）；項目要原樣保留，移除過的不能回來
- 規則：
  - `add`：長度不在 `[MIN_LENGTH, MAX_LENGTH]` → 錯誤 `length_out_of_range`（不登記）。`hmac = HMAC-SHA256(key, UTF-8(secret))`；已有相同長度且相同 HMAC（固定時間比較）的項目 → 錯誤 `already_registered`。標籤：`null` 或全空白 → 「未命名」（zh-TW），否則 trim 後截到前 `MAX_LABEL_LENGTH` 個 code unit。
  - `find`：`null` 或空字串或沒有項目 → 空。文字超過 `MAX_SCAN_LENGTH` 只看前 `MAX_SCAN_LENGTH` 個 code unit。對每個已登記的長度 L，從頭滑動所有長度 L 的子字串算 HMAC 比對；**每個項目最多回報一次**（第一次出現的位置）。結果依位置排序，每筆是 `kind: registered`、`label`、`span_utf16`，`masked` 是「已登記的「{label}」」——**不含任何原文字元**。
- `expect`：
  - `add` 事件：
    - `ok`：bool
    - `error`：`length_out_of_range` | `already_registered`
    - `label`：存下來的標籤
    - `length_utf16`：存下來的長度
    - `hmac_hex`：存下來的 HMAC（小寫 hex）
    - `hmac_hex_not`：存下來的 HMAC 不能等於這個值（用來寫明「不是 SHA-256(secret)」）
  - `find` 事件：`matches`（**完整**結果，每筆只寫有檢查的欄位：`kind`、`label`、`span_utf16`）、`count`、`masked_not_contain`（Text 陣列）
  - `remove` 事件：`removed`：bool
  - 任何事件：`entries_count`：事件後的項目數

## `registered.validate`

舊版 `SecretRegistration.Validate(secret, confirm)`：「登記機密」對話框的輸入檢查。錯誤訊息顯示在有問題的那一欄旁邊，**不含輸入的內容**。

- `args`：`secret`、`confirm`：Text | null（`null` 等同空字串）
- 規則（依序）：`secret` 空 → `secret` 欄「請輸入要登記的機密。」；長度不在 6–256 → `secret` 欄「機密長度需 6–256 字元，目前 N 字元。」；`confirm` 空 → `confirm` 欄；兩者不同 → `confirm` 欄「兩次輸入的內容不一樣，請重新輸入。」；否則通過。標籤可以留空；重複登記由 `registered.run` 的 `add` 判斷。
- `expect`：
  - `ok`：bool（通過 = `true`）
  - `field`：`secret` | `confirm`
  - `message`：完整訊息；`message_contain` / `message_not_contain`：子字串陣列
