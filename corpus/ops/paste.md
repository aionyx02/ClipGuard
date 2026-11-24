# paste

貼上攔截（嚴格模式，§5.3）。視窗與行程是純資料。

**設定物件** `settings`（各 op 共用；欄位沒寫 = 預設值）：
- `intercept_registered`：bool，剪貼簿含登記的機密時攔截。預設 `true`
- `intercept_detected`：bool，含偵測到的個資／API key 時攔截。預設 `false`
- `allowed_apps`：字串陣列，使用者的允許清單（行程名稱）。預設 `[]`

**kind** 同 `secret.find`（`registered`、`credit_card`、`national_id`、`mobile_phone`、`api_key`、`business_id`、`resident_certificate`…）。

## `paste.decide`

舊版 `PasteGuard.Decide(kinds, target, settings)`：按下 Ctrl+V／Shift+Insert 時要不要攔。

- `args`：
  - `kinds`：剪貼簿機密摘要裡的 kind 陣列（可空）
  - `target`：`{"process": string, "class": string, "own": bool}`（`own` 沒寫 = false；`own` = 目標是 PasteWarden 自己的視窗）
  - `settings`：見上
- 規則：`kinds` 空或 `own` → `allow`。`applies = (intercept_registered 且含 registered) 或 (intercept_detected 且含任何非 registered 的 kind)`；不 applies → `allow`。目標在允許清單 → `allow`；否則 `intercept`。
  - 允許清單：`own`；或 `class` **精確**等於內建 class `Credential Dialog Xaml Host`；或 `normalize(process)` 非空且（不分大小寫）**完全等於**內建清單 `1Password, KeePass, KeePassXC, Bitwarden, Dashlane, Enpass, Keeper, RoboForm, NordPass, ProtonPass, LastPass, CredentialUIBroker, consent` 或 `settings.allowed_apps` 裡某一項的 `normalize` 結果（不是子字串比對）。
- `expect`：
  - `decision`：`allow` | `intercept`

## `paste.can_intercept`

舊版 `PasteGuardSettings.CanIntercept(hasRegisteredSecrets)`：設定有沒有可能攔截任何東西（不可能時 App 不裝鍵盤 hook）。

- `args`：`settings`；`has_registered`：bool，是否有登記的機密
- 規則：`intercept_detected || (intercept_registered && has_registered)`
- `expect`：`can_intercept`：bool

## `paste.normalize_app`

舊版 `PasteGuard.NormalizeAppName(name)`：去掉前後空白、路徑（最後一個 `\` 或 `/` 之前）和結尾 `.exe`（不分大小寫），再 trim。`null` 或全空白 → `""`。

- `args`：`name`：string | null
- `expect`：`output`：string

## `paste.snapshot`

舊版 `ClipboardSecretSnapshot.From(sequence, SecretDetector.Find(text))`：剪貼簿機密摘要，只留 kind、label、遮罩字串和剪貼簿序號，不留原文和位置。

- `input`：Text，剪貼簿文字（用 `secret.find` 預設個資包找機密）
- `args`：`sequence`：整數（剪貼簿序號）
- `expect`：
  - `sequence`：整數
  - `secrets`：**完整**的摘要陣列，每筆只寫有檢查的欄位（`kind`、`label`、`masked`）
  - `masked_not_contain`：所有 `masked` 都不能包含這些字串
  - `kinds`：去重後的 kind 陣列（依第一次出現的順序）

## `paste.mask`

舊版 `PasteGuard.MaskText(text, matches)`：「貼上遮罩版」用，把每一筆機密換成遮罩。

- `input`：Text
- `args`：
  - `matches`：`"detect"` = 用 `secret.find`（預設個資包）對 `input` 找；或明確的陣列，每筆 `{"kind", "label", "masked", "span_utf16": [index, length]}`
- 規則：依 index 排序；與前一筆重疊或超出文字範圍的略過。`registered` → 固定 `********`（8 個 `*`，不帶標籤、不洩漏長度）。PEM 私鑰標頭（kind `api_key`，masked 以 `-----BEGIN ` 開頭、以 `PRIVATE KEY-----` 結尾）→ `masked + "\n" + 私鑰本文遮罩訊息 + "\n"`，並一路吃到下一個 `-----END `（不含），沒有 END 就到結尾。其他 → `masked`。
- `expect`：
  - `output`：Text，完整結果
  - `starts_with` / `ends_with`：Text
  - `contains` / `not_contains`：Text 陣列
  - `contains_pem_body_mask`：`true` = 結果含有私鑰本文遮罩訊息（zh-TW「（私鑰內容已遮罩）」）
  - `redetect_empty`：`true` = 對結果再跑一次 `secret.find`（預設個資包）沒有任何結果

## `paste.enter`

舊版 `PasteGuard.ShouldSwallowEnter`：攔下貼上、使用者還沒決定時，Enter 要不要吞掉（防止在確認框搶到焦點前按下聊天程式的送出）。這裡寫成事件序列，等待時間由 `t_ms` 算出。每個案例從「沒有在等」開始。

- 常數 `PENDING_TIMEOUT_MS = 60000`：等超過就當成取消，保證不會卡住。
- `events`：每個事件有 `t_ms` 和下面其中一種動作：
  - `"intercept": {"target_root": 整數}` ：攔下一次貼上，開始等待。`target_root` = 貼上目標的最上層視窗（`0` = 查不到）。
  - `"resolve": true` ：使用者做了決定（或取消），結束等待。
  - `"enter": {"foreground_root": 整數, "foreground_is_own": bool}` ：使用者按 Enter，可帶 `expect`。
- 規則：`swallow = 正在等 且 (t_enter - t_intercept) < PENDING_TIMEOUT_MS 且 !foreground_is_own 且 target_root != 0 且 foreground_root == target_root`
- `expect`（`enter` 事件）：`swallow`：bool

## `paste.settings_load`

舊版 `PasteGuardSettingsStore.Load`：解析設定檔（JSON，欄位 `InterceptRegistered`、`InterceptDetected`、`AllowedApps`）。檔案位置與寫入方式不在這裡（由平台層決定）；Rust 版的設定格式可以不同，但「缺欄位用預設、壞檔回預設並回報錯誤、清單要清理」的語意要一樣。

- `args`：`file`：Text | null（檔案內容；`null` = 檔案不存在）
- 規則：不存在 → 預設、沒有錯誤。解析失敗 → 預設、有錯誤。缺的欄位用預設。`allowed_apps` 經過清理：每項 `normalize`、丟掉空的和超過 `MAX_APP_NAME_LENGTH = 100` 字的、不分大小寫去重（留第一個）、最多 `MAX_ALLOWED_APPS = 100` 項。
- `expect`：
  - `error`：bool，有沒有回報錯誤
  - `settings`：`{intercept_registered, intercept_detected, allowed_apps}`，只寫有檢查的欄位
  - `allowed_apps_count`：整數

## `paste.settings_save`

舊版 `PasteGuardSettingsStore.Save` 後再 `Load`：存檔時套用和讀檔相同的清理。

- `args`：`settings`（見上）
- `expect`：同 `paste.settings_load`（`settings`、`allowed_apps_count`、`error`）
