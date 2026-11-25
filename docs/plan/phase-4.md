# Phase 4：桌面版（4a Windows、4b 其他平台）

> 分支：`feature/phase-4-desktop` → PR 到 `dev`（Phase 3 的 PR 已合併）
> 依賴：core 的 `policy::{guard, entry, throttle, paste, registered, windows}`、`wallet::swap`（Phase 1）；`crates/report`（Phase 2 §2.2）。
> 參考：`docs/spikes/s3-windows-monitor.md`、`s9-native-messaging.md`（4b 另參考 S4、S5、S6）；`docs/spec/detection-rules.md` §2、§4、§5.1、§5.3、§6.2；`docs/THREAT_MODEL.md` T1、T5、T6、T15、T16

## 4.1 範圍

Phase 4 拆成兩段。**4a** 讓 Windows 和舊版 ClipGuard 的功能完全對等，再加上 Windows 的 Native Messaging；完成條件就是 roadmap 寫的「Windows 手動測試清單（含舊 #9）全部通過」。**4b** 做 macOS、Linux、Android，照 S4、S5、S6 的建議做法，規格見 §4.9。

這樣拆是因為發表現場是 Windows（roadmap 開頭），而 4a 完成時離發表日不到兩週。4b 原本排在 4a 之後；現在改成由 macOS 上的另一位成員平行開發（分支 `feature/phase-4b-macos`，從本分支拉出，完成後合併回本分支，Phase 4 仍然只有一個 PR）。4b 不會擋 Phase 4 的完成條件：沒做完的平台照 §4.9.5 處理，發表時只有瀏覽器端的保護。

兩段共用的部分（`PasteGate`、`ProtectionStatus`、UI、設定、Native Messaging 協定）由 4a 定義。4b 只新增 `crates/platform/src/{macos,linux,android}/` 和平台專屬的設定。要改共用部分時，先在 #43 上和 4a 對齊。

判斷邏輯都已經在 core 裡，4a 只寫平台介接（`crates/platform`）和 UI 接線（`apps/desktop`），不改偵測行為（P7）。core 的介面不夠用時，先改 `docs/spec/detection-rules.md` 再改 core。

| 元件 | 位置 | 技術 |
|---|---|---|
| 平台介接 | `crates/platform/src/windows/` | `windows` crate；`#[cfg(windows)]` |
| 設定與登記機密的儲存 | `crates/platform/src/store.rs` | JSON 檔＋OS keyring（Windows Credential Manager） |
| Native Messaging host | `crates/platform/src/bin/paste-warden-nmh.rs` | 獨立的小 binary（S9：大型執行檔的 spawn 時間太長） |
| 桌面 App | `apps/desktop` | Tauri v2＋React＋TypeScript＋Tailwind；權限寫在 `src-tauri/capabilities/*.json`，禁用 v1 API |

## 4.2 執行緒

| 執行緒 | 負責的事 | 限制 |
|---|---|---|
| `main` | Tauri 事件迴圈、系統匣、所有視窗 | 不呼叫 core 的分析函式 |
| `pw-clip` | message-only window：`AddClipboardFormatListener`、`SetWinEventHook(EVENT_SYSTEM_FOREGROUND)`，所有 `OpenClipboard` 都用這個 hwnd | 只讀資料、轉成事件，不分析 |
| `pw-hook` | `WH_KEYBOARD_LL`，只跑訊息迴圈，優先權 `THREAD_PRIORITY_HIGHEST` | callback 不配置記憶體、不拿鎖、不做 IO，只讀 `PasteGate` |
| `pw-work` | 持有 core 的所有狀態機，負責分析和決策，透過 `AppHandle` 把結果送給 UI | 不碰 Win32 視窗訊息 |

```
 pw-clip ──ClipEvent/FgEvent──┐
 pw-hook ──HookEvent─────────┼──mpsc──► pw-work（core 狀態機）
 Tauri invoke ──UiCommand────┘             │ 寫入
                                           ▼
                     PasteGate（atomic）◄── pw-hook 只讀
                                           │ emit
                                           ▼
                                main：通知、確認框、系統匣
```

`PasteGate` 是唯一跨執行緒共用的狀態，全部是 atomic：`analyzed_seq: AtomicU32`、`decision: AtomicU8`（`Allow`／`Intercept`／`Unknown`）、`fg_root: AtomicIsize`、`fg_allowed: AtomicU8`、`pending_target: AtomicIsize`（0 代表沒有等待中的確認框）。前景視窗是否在允許清單內，由 `pw-work` 在前景切換時先算好，所以 hook callback 不必查行程名稱（S3：callback 超過約 615 ms 就 fail-open）。

## 4.3 輸入與常數

所有上限、時間、名稱都寫成具名常數。標成「自訂」的值是本 Phase 定的，理由寫在表後；其他值沿用規格或 spike 實測，不能改。視窗 class、行程名稱這類資料放進 `rules/policy/windows.json`。core 已經有的常數直接引用，不重新定義。

### 剪貼簿變動（`windows/clipboard.rs`）

| 常數 | 值 | 來源 |
|---|---|---|
| `OPEN_RETRY_COUNT`／`OPEN_RETRY_DELAY_MS` | `20`／`5` | S3 |
| `MAX_ANALYZED_CHARS` | 引用 `core::limits` | §2.2 |
| `FORMAT_EXCLUDE_MONITOR` | `"ExcludeClipboardContentFromMonitorProcessing"` | S3 |
| `FORMAT_HISTORY_FLAG` | `"CanIncludeInClipboardHistory"`，值為 0 才略過；單獨的 `CanUploadToCloudClipboard=0` 照常分析 | S3 發現 7 |
| `FORMAT_CHROMIUM_SOURCE_URL`／`FORMAT_HTML` | `"Chromium internal source URL"`／`"HTML Format"`（讀標頭的 `SourceURL:`） | S3 發現 2 |
| `SOURCE_URL_MAX_BYTES` | `2_048` | 自訂 |
| `HTML_HEADER_SCAN_BYTES` | `4_096`：CF_HTML 只掃這麼多 bytes 找 `SourceURL:`，不讀頁面內容 | 自訂 |
| `CLIPBOARD_READ_DELAY_MS` | `25`：收到 `WM_CLIPBOARDUPDATE` 後延遲再讀，期間有新通知就重新計時 | 實測（見下） |
| `CLIPBOARD_COMMAND_TIMEOUT_MS` | `1_000`：其他執行緒等 `pw-clip` 執行寫入、清空、快照的上限 | 自訂 |
| `MAX_IMAGE_PATH_UNITS` | `32_768`：`QueryFullProcessImageNameW` 的緩衝區（UTF-16 單位） | Win32 路徑上限 |
| 去重 | `(GetClipboardSequenceNumber, SHA-256(分析用的前綴))`，只記最後一組 | S3 發現 4 |
| `SELF_WRITE_SUPPRESS_MS`／`SELF_WRITE_CACHE_LEN` | `3_000`／`4` | §5.3／自訂 |
| `RUN_INITIAL_CHECK` | `true`，啟動後立刻分析現有剪貼簿 | 舊 #9 |
| `MASKED_PASTE_RESTORE_DELAY_MS` | `600` | §5.3 |
| `RESTORE_TEXT_FORMATS` | `CF_UNICODETEXT`、`Rich Text Format`、`HTML Format`、`CSV`；寫入時附加 `CanIncludeInClipboardHistory=0` | §5.3 |

來源判斷的順序是剪貼簿 metadata 的來源網址、剪貼簿 owner、變動前的前景視窗（S3 發現 5）。owner 是 `powershell` 不算可疑訊號（S3 發現 4）。

**為什麼要延遲讀取**：C1 的整合測試發現，收到通知就立刻打開剪貼簿時，用 .NET `Clipboard.SetText` 複製的程式 20 次裡有 11 次失敗（對照組沒開監看程式時 0 次）。.NET 寫入後會再打開一次剪貼簿呼叫 `OleFlushClipboard`，被我們搶先打開就會丟出例外，使用者會在那個程式裡看到錯誤。延遲 25 ms 之後連續 4 輪、共 80 次寫入都沒有失敗（`crates/platform/tests/windows_clipboard.rs` 的 `external_writers_are_not_disturbed`）。代價是 §5.3 已知限制裡「複製後很快按 Ctrl+V，危險指令仍會被貼出去」的時間窗會多約 25 ms，C7 實測後更新 detection-rules.md 的數字。

**自我寫入**：我們寫入時會加上 `CanIncludeInClipboardHistory=0`，看起來跟密碼管理器的內容一樣。所以自我寫入快取同時記下寫入後的序號，序號相符就不看這個標記、照常讀取並標成 `self_write`。

### 前景視窗（`windows/foreground.rs`）

| 常數 | 值 | 來源 |
|---|---|---|
| `WINEVENT_FLAGS` | `WINEVENT_OUTOFCONTEXT \| WINEVENT_SKIPOWNPROCESS` | S3 |
| `FOREGROUND_HISTORY_LEN`／`WINDOW_TITLE_MAX_CHARS` | `16`／`256` | 自訂 |
| `uwp_host_process`／`uwp_frame_class`（`rules/policy/windows.json`） | `"ApplicationFrameHost"`／`"ApplicationFrameWindow"` | S3 發現 6 |
| `MAX_WARNED_WINDOWS` | 引用 `core::policy::entry` | §4 |

UWP 用 `EnumChildWindows` 找 PID 和 frame host 不同的子視窗，找不到就回報「未知」，等下一次前景事件。

### 貼上按鍵（`windows/paste_hook.rs`）

| 常數 | 值 | 來源 |
|---|---|---|
| `PASTE_COMBOS` | Ctrl+V、Ctrl+Shift+V、Shift+Insert | §5.3、S3 |
| `SELF_INPUT_TAG` | `0x5057_0001`（`dwExtraInfo`；不能用 `LLKHF_INJECTED` 判斷） | S3 發現 3；值自訂 |
| `PROBE_VK` | `VK_F24` | S3 |
| `HOOK_PROBE_INTERVAL_MS`／`HOOK_PROBE_DEADLINE_MS` | `30_000`／`1_000` | 自訂 |
| `HOOK_FAIL_OPEN_MS` | `615`（文件常數，只當測試門檻） | S3 實測 |
| `CALLBACK_BUDGET_US` | `100` | 自訂 |
| `PENDING_ANALYSIS_TIMEOUT_MS` | `2_000` | 自訂 |
| `PENDING_TIMEOUT_MS`、`REGISTERED_MASK`、`MAX_ALLOWED_APPS`、`MAX_APP_NAME_LENGTH` | 引用 `core::policy::paste` | §5.3 |
| `HOOK_PROBE_FAIL_THRESHOLD` | `2`：連續 2 次探測失敗才顯示「失效」，第 1 次只重裝 hook | 自訂 |
| 探測暫停條件 | 前景視窗的 integrity level 高於自己（系統管理員視窗）、工作階段鎖定中（`WTSRegisterSessionNotification` 的 `WTS_SESSION_LOCK`/`UNLOCK`）、secure desktop（UAC 提示） | S3＋自訂，理由見 §4.8 |

`PasteGuardSettings::can_intercept` 為 false 時不裝 hook；結束程式時先拔 hook。

### 錢包掉包用的輸入時間（`windows/input.rs`）

只用 `GetLastInputInfo`，不裝 hook、不記錄按鍵。時間常數引用 `core::wallet::swap`（`FAST_WINDOW_MS`、`WINDOW_MS`、`COPY_INPUT_GRACE_MS`）。時間由 `pw-work` 取得後傳進 core。

### 設定與登記機密（`store.rs`）

| 常數 | 值 | 來源 |
|---|---|---|
| `DATA_DIR` | `%LOCALAPPDATA%\PasteWarden` | 舊版位置改名 |
| `SETTINGS_FILE`／`PASTE_GUARD_FILE`／`SECRETS_FILE` | `settings.json`／`paste-guard.json`／`secrets.json` | 自訂／§5.3／§5.1 |
| `STORE_FILE_MAX_BYTES` | `65_536`，超過當作損毀 | 自訂 |
| `KEYRING_SERVICE`／`KEYRING_ACCOUNT` | `"PasteWarden"`／`"registered-secrets-hmac-key"` | 自訂 |
| `KEY_LENGTH`、`MIN_LENGTH`、`MAX_LENGTH`、`MAX_LABEL_LENGTH`、`MAX_SCAN_LENGTH` | 引用 `core::policy::registered` | §5.1 |
| `MAX_REGISTERED_SECRETS` | `100` | 自訂 |
| `LEGACY_DATA_DIR`／`LEGACY_FILES` | `%LOCALAPPDATA%\ClipGuard`／`secrets.json`、`key.bin`、`paste-guard.json` | 舊版 |

金鑰讀不到時直接報錯，不自動重建（§5.1）。

### Native Messaging（`bin/paste-warden-nmh.rs`）

| 常數 | 值 | 來源 |
|---|---|---|
| `NMH_NAME` | `"org.pastewarden.nmh"` | 自訂 |
| `NMH_PROTOCOL_VERSION` | `1` | S9 |
| `NMH_MAX_MESSAGE_BYTES` | `65_536`，超過就結束、不先配置記憶體 | S9 |
| `BROWSER_HOST_MESSAGE_LIMIT_BYTES` | `1_048_576`（文件常數） | S9 實測 |
| `NMH_OPS` | `hello`、`policy.get`、`verdict`、`match_registered`；未知的 op 回 `unknown_op` | S9 |
| `IPC_PIPE_NAME` | `\\.\pipe\paste-warden-<使用者 SID>`，ACL 只給本人 | 自訂 |
| `IPC_TIMEOUT_MS` | `500`；桌面 App 沒執行時回 `desktop: "not_running"`，不啟動 GUI | 自訂 |
| `EXT_PROBE_RETRY_MS`／`EXT_PROBE_RETRY_MAX_MS` | `600_000`／`3_600_000` | 自訂 |

訊息裡不放剪貼簿或輸入框的原文、遮罩前的機密、完整網址（只放 host）、HMAC 金鑰；host 不提供讀剪貼簿或讀機密的 op（T16）。

S9 的 Windows 實測結果決定了三件事。第一，安裝程式寫 `HKCU\Software\{Google\Chrome,Microsoft\Edge,Chromium,Mozilla}\NativeMessagingHosts\org.pastewarden.nmh` 四個 key，解除安裝時全部刪除。第二，argv 的第 3 個參數是 `--parent-window=<HWND>`，host 要接受它，只比對第 2 個參數的 extension ID。第三，`sendNativeMessage` 單次呼叫在 Windows 上約 50–60 ms，只用在啟動探測和偶爾的 `verdict`，需要即時回覆的 op 一律走 `connectNative`。

### UI 指令（`apps/desktop/src-tauri/src/commands.rs`）

`restore`、`set_paste_guard { registered, detected }`、`allowlist_add`／`allowlist_remove(name)`、`register_secret { secret, confirm, label }`、`list_secrets`、`remove_secret(id)`、`set_locale`（`system`／`zh-TW`／`en`）、`set_theme`（`system`／`light`／`dark`）、`paste_choice`（`cancel`／`masked`／`original`）、`get_protection_status`（§4.8.1）、`quit`。所有參數都在 Rust 端用 core 的檢查函式重新驗證；`register_secret` 收到後立刻放進 `Zeroizing`，錯誤只回欄位和訊息 ID。每個視窗的 capability 只開它需要的指令。

### 自訂值的理由

- `HOOK_PROBE_INTERVAL_MS = 30_000`、`HOOK_PROBE_DEADLINE_MS = 1_000`：S3 連續 14 次逾時都沒看到 hook 被移除，失效應該很少見；30 秒探測一次的成本是每分鐘 2 個被吞掉的 F24。1 秒的期限遠大於實測的 `SendInput → callback` p99（約 0.26 ms）。
- `CALLBACK_BUDGET_US = 100`：實測最長 14.8 µs，留約 7 倍的餘裕，又比 fail-open 門檻低四個數量級。
- `PENDING_ANALYSIS_TIMEOUT_MS = 2_000`：1 Mi 字的病態輸入在 release 下約 150 ms（§6.1）；超過 2 秒代表出了問題，這時**不補送**按鍵（fail closed），改跳 Warning 通知。
- `SOURCE_URL_MAX_BYTES`、`WINDOW_TITLE_MAX_CHARS`、`STORE_FILE_MAX_BYTES`、`MAX_REGISTERED_SECRETS`、`FOREGROUND_HISTORY_LEN`、`SELF_WRITE_CACHE_LEN`：讓每個外部輸入都有上限；值取正常使用的數倍。
- `IPC_TIMEOUT_MS = 500`：named pipe 在本機的來回時間是毫秒以下，500 ms 夠讓忙碌中的桌面 App 回應，又不會讓擴充功能等太久。

## 4.4 流程

### 剪貼簿變動

```
WM_CLIPBOARDUPDATE（pw-clip）
  ├─ 序號＋雜湊與上一筆文字相同 → 丟掉（空的剪貼簿會清掉這筆記錄）
  ├─ 有 Exclude 標記，或 History=0 → 只送 Empty 事件，不讀文字
  └─ 讀 CF_UNICODETEXT 前 1 Mi 字＋來源網址＋owner → ClipEvent
       （雜湊在自我寫入快取內 → self_write：照常分析、不發通知）
pw-work：
  ① guard.on_clipboard_text → Quarantine：清空、存隔離區、紅色通知
  ② 機密 ③ 隱藏字元 ④ 錢包（帶 GetLastInputInfo 的時間）
  ⑤ 更新 PasteGate.analyzed_seq / decision → throttle.submit
```

### 貼上攔截

```
Ctrl+V 等（pw-hook callback，只讀 atomic）
  ├─ dwExtraInfo == SELF_INPUT_TAG → 放行
  ├─ 前景 == fg_root 且 fg_allowed → 放行
  ├─ GetClipboardSequenceNumber != analyzed_seq → 吞掉，通知 pw-work
  │     └─ 等分析，最多 2 s：Allow 就帶標記補送；逾時不補送、跳 Warning
  ├─ decision == Allow → 放行
  └─ Intercept → 吞掉（連同放開事件），pw-work 開確認框
        取消（Enter／Esc／60 s）│ 貼遮罩版 │ 貼原文
```

確認框還沒做決定時，送往 `pending_target` 的 Enter 也吞掉（`PendingPaste::should_swallow_enter`）。貼遮罩版照 §5.3：暫時寫入遮罩版、切回原視窗、送出帶標記的 Ctrl+V、600 ms 後換回；期間使用者又複製了別的東西就不換回。

### hook 健康檢查

```
每 30 s：pw-work 檢查探測暫停條件（§4.3）
  ├─ 前景是系統管理員視窗／工作階段鎖定／secure desktop → 這一輪不探測，記為 skipped
  └─ 送出帶標記的 F24
       ├─ 1 s 內 callback 收到（並吞掉）→ 正常，失敗次數歸零
       └─ 沒收到 → 失敗次數 +1，重裝 hook，30 s 後再探測一次
            └─ 連續 HOOK_PROBE_FAIL_THRESHOLD 次 → ProtectionStatus.intercept = Degraded(HookLost)
                 UI 顯示「貼上保護暫時失效」，系統匣圖示改成警示狀態
                 └─ 下一次探測收到 → 清掉提示
```

為什麼要暫停：送往系統管理員視窗的 `SendInput` 會被 UIPI 擋下，而且**回傳值和 `GetLastError` 都看不出失敗**（Win32 文件寫明）；鎖定畫面和 UAC 的 secure desktop 也一樣。在這些情況下探測一定會失敗，如果不暫停，使用者每次開系統管理員終端機都會看到誤報的「hook 失效」。所以探測失敗只代表 hook 本身出問題；系統管理員視窗的情況由 §4.8 另外告知。

### 執行入口守衛與還原

前景切換時用 `entry::classify_with(&windows_rules().entry, class, title, process)` 判斷入口，`entry::decide_for(entry, guard.level(), guard.quarantine_active())` 決定紅黃提醒，再經過 `EntryWarningGate::try_enter(hwnd, guard.generation())`；同時算好 `fg_allowed` 寫進 `PasteGate`。還原從系統匣選單觸發：`begin_restore` 先把內容標為可信，再寫入剪貼簿，最後 `end_restore(ok)`。

### Native Messaging

```
擴充功能啟動 → sendNativeMessage({op:"hello"})
  ├─ 失敗 → desktop=absent，安靜降級，10 分鐘後重試（backoff 到 60 分鐘）
  └─ 成功 → paste-warden-nmh 透過 named pipe 問桌面 App
              ├─ 沒在執行 → desktop:"not_running"
              └─ 執行中 → 交換版本與 caps；之後只送 verdict（規則 ID、
                 嚴重度、host）和 match_registered（擴充功能先算好的 HMAC）
```

`nativeMessaging` 放在擴充功能的 `optional_permissions`，裝了桌面版才請求。

## 4.5 已決定的事項與偏離

| 項目 | 決定 | 原因 |
|---|---|---|
| 通知 | 用 `tauri-plugin-notification`（Windows toast），throttle 照常執行。**偏離 §2.1**：做不到「撤掉已顯示的舊通知」和「點擊通知還原」，還原一律從系統匣選單 | 自己做通知視窗的成本留到之後；「一次複製最多一則」和「過期的不顯示」仍由 throttle 保證 |
| 舊版資料 | 不遷移。啟動時只刪 `LEGACY_FILES` 列出的三個檔案，資料夾空了才刪資料夾，並跳一次通知請使用者重新登記 | 舊的 HMAC 金鑰由 DPAPI 保護，新版改用 keyring |
| 擴充功能 ID | 用 manifest 的 `key` 固定 Chrome、Edge 的 ID，Firefox 用固定的 gecko id，三個都寫進 `allowed_origins`／`allowed_extensions` | roadmap 決定不上架 Chrome Web Store，沒有商店 ID |
| 重複警告 | 瀏覽器內發生的事由擴充功能顯示；桌面版收到 `verdict` 只記錄、不跳通知 | 擴充功能知道是哪個分頁，能在頁面上直接顯示 |
| CI | hook 相關測試標成 `#[ignore]`，只在本機和手動清單驗證；CI 只跑純邏輯測試和建置 | Windows runner 能不能裝低階 hook 未確認 |
| 簽章 | 4a 不處理，留給 Phase 6；下載頁教使用者用圖形介面按「仍要執行」 | S3 待決問題 3 |
| CLI 的 Report JSON | Phase 4 前已改成直接用 `crates/report`（phase-2.md 實作備註的要求）；`crates/cli/src/report_json.rs` 和 parity 測試刪除。JsonSchema 放在 `crates/report` 的 `schema` feature，只有 CLI 開啟 | 一份實作就不需要 parity 測試；WASM 不必帶 schemars |

## 4.6 測試

- 單元測試：`crates/platform` 的純邏輯（去重、自我寫入快取、`PasteGate` 的編碼、儲存檔損毀與過大、舊版資料只刪列出的檔案）一律把時間當參數傳入。keyring 用 mock 後端。
- 整合測試（`#[ignore]`，本機執行）：真的剪貼簿（測試前備份、結束時還原）；同一個行程用 `SendInput` 送帶標記的 F24，斷言 callback ≤ `CALLBACK_BUDGET_US`。跨行程的逾時行為手動測一次。
- Native Messaging：Chromium E2E 用 Playwright 的暫存 `user-data-dir`；Windows 的 registry 只寫 HKCU，測完刪掉。
- 手動測試清單（C7 補上）：舊 #9 的 4 項（系統匣還原且還原後不再被攔、通知文字完整、啟動時現有的剪貼簿會被分析、第二個實例直接結束）、§4 的入口表、§5.3 的已知限制。

## 4.7 完成條件

- [x] CLI 改用 `crates/report`。
- [x] S9 的 Windows 部分（registry 位置、`--parent-window`、stdout 是否為 binary mode）實測，結果寫回 `s9-native-messaging.md`。Chromium、Edge 已測；這台電腦沒有 Firefox，Windows 的 Firefox 放進手動測試清單。
- [ ] `crates/platform` 的 Windows 元件與 §4.6 的測試。
- [ ] `apps/desktop`：系統匣選單和舊版對等、通知、確認框、登記和管理機密、允許清單、設定頁、深淺色、語言（`locales/{zh-TW,en}/ui-desktop.ftl`，前綴 `ui-desktop-`）。
- [ ] `paste-warden-nmh` 與擴充功能的探測、降級。
- [ ] `cargo tauri build` 產出 msi 與 nsis 安裝檔。
- [ ] §4.8：`ProtectionStatus`、探測暫停、系統管理員視窗與右鍵貼上的告知（Windows）。
- [ ] Windows 手動測試清單全部通過（含 §4.8.4 新增的項目）。
- [ ] 4b：§4.9.5 的必要項目完成；沒完成的平台照 §4.9.5 處理並寫明原因。

## 4.8 保護範圍的誠實告知（4a 補充，4b 共用）

S3 實測有兩種情況攔不到貼上：**右鍵／選單的「貼上」**（不經過鍵盤）和**系統管理員視窗**（UIPI 讓低階 hook 收不到按鍵）。這兩種情況在 Windows 上沒辦法修好，只能讓使用者知道。原則是：**在使用者以為受到保護、實際上沒有的時候，一定要看得到提示**。

### 4.8.1 `ProtectionStatus`（`crates/platform/src/status.rs`，平台無關、純邏輯）

```rust
pub struct ProtectionStatus {
    pub watch: Capability,      // 背景監聽剪貼簿
    pub write: Capability,      // 清空、遮罩後寫回、還原
    pub foreground: Capability, // 前景視窗（入口警告、允許清單）
    pub intercept: Capability,  // 貼上前攔截
}
pub enum Capability { Active, Degraded(Reason), Unavailable(Reason) }
```

`Reason` 是列舉，每個值對應一個 Fluent 訊息 `ui-desktop-status-<reason>`（platform 和 core 一樣不產生給人看的文字）。4a 用到的值：`HookLost`、`ElevatedForeground`、`DisabledInSettings`。4b 新增的值見 §4.9.4。

- `pw-work` 是唯一能改 `ProtectionStatus` 的執行緒，每次改變都 emit `protection-status` 事件給 UI，UI 也能用 `get_protection_status` 指令主動查詢（加進 §4.3 的 UI 指令表，capability 只開給主視窗和系統匣）。
- 系統匣圖示有三種狀態：正常、部分降級（任何一項是 `Degraded`）、失效（`intercept` 或 `watch` 是 `Unavailable`，而且設定上是開著的）。tooltip 列出每一項降級的原因。

### 4.8.2 系統管理員視窗

- 前景切換時，`pw-work` 用 `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` 加 `GetTokenInformation(TokenIntegrityLevel)` 比較前景行程和自己的 integrity level（S3：系統管理員行程也查得到），結果寫進 `ForegroundInfo.elevated`。查詢失敗時當作「是」（fail closed：寧可多告知一次）。
- 前景是較高 integrity 的視窗時，`intercept = Degraded(ElevatedForeground)`，離開後恢復。系統匣圖示跟著變，但**不跳通知**，因為使用者常常開著系統管理員終端機，每次切換都跳通知會很吵。
- **會跳通知的情況**：剪貼簿目前的判定是 `Intercept`（裡面有機密，或使用者登記的機密），而且使用者切到系統管理員視窗。每組 `(hwnd, 剪貼簿序號)` 最多一次，經過 throttle。訊息 `ui-desktop-toast-elevated-unprotected`，內容只說「這個視窗以系統管理員身分執行，PasteWarden 攔不到這裡的貼上；剪貼簿裡有 {kind}」，`kind` 是機密種類，不含任何內容。
- 惡意指令不受這個限制影響：嚴格模式在**複製的當下**就清空剪貼簿（§4.4 的 ①），所以貼到系統管理員終端機也貼不出東西；入口警告也照常顯示。設定頁要把這一點寫清楚，避免使用者以為系統管理員視窗完全沒有保護。
- 「用系統管理員身分執行 PasteWarden，讓 hook 收得到」列在 §4.10 待決問題，4a 不做。

### 4.8.3 右鍵貼上、拖放、其他貼上方式

hook 只看得到 §4.3 `PASTE_COMBOS` 列的按鍵。右鍵選單、App 的「編輯 → 貼上」選單、拖放、遠端桌面的剪貼簿同步都攔不到。

- **設定頁的「保護範圍」區塊**：用一張表列出「複製當下（清空、遮罩）」和「貼上前確認」各自涵蓋哪些貼上方式，右鍵、選單、拖放那幾格明確寫「不涵蓋」，並說明惡意指令在複製時就清掉，所以仍然受保護；**機密的貼上前確認則不涵蓋**。表格旁邊即時顯示 §4.8.1 的狀態。
- **第一次執行的導覽**有一頁專門講這件事（訊息 `ui-desktop-onboarding-limits-*`），使用者必須按「我知道了」才能進下一頁。
- 貼上攔截的設定說明（`set_paste_guard` 的開關旁邊）要提一次「只攔鍵盤貼上」。
- 文件網站的平台限制頁（`apps/docs`）同步寫一份。

### 4.8.4 測試

- 單元測試：探測排程器（時間當參數）在三種暫停條件下記為 skipped、不累計失敗；連續 2 次失敗才變成 `HookLost`；`ElevatedForeground` 的通知每組 `(hwnd, seq)` 最多一次；integrity 查詢失敗時當作已提權。
- 手動測試清單新增：
  1. 開著系統管理員 Windows Terminal 兩分鐘以上，不會出現「hook 失效」。
  2. 複製一筆假的機密，切到系統管理員終端機，跳出一次通知；再切走、切回來不會重複跳。
  3. 複製惡意指令樣本，貼到系統管理員終端機，貼不出東西。
  4. 右鍵貼上機密：會貼出去（已知限制），而且設定頁的「保護範圍」表格和實際行為一致。
  5. 鎖定畫面一分鐘後解鎖，不會出現「hook 失效」。
  6. dev build 的除錯指令 `debug_drop_hook` 拔掉 hook：約 60 秒內 UI 顯示失效，系統匣圖示改變；`debug_restore_hook` 後恢復。這兩個指令只存在於 `cfg(debug_assertions)`。

## 4.9 4b：macOS、Linux、Android

4b 沿用 4a 的執行緒分工（§4.2）、`PasteGate`、`ProtectionStatus`、UI、`store.rs` 介面和 Native Messaging 協定，只換掉平台介接。下面只寫和 Windows 不同的部分；沒寫的常數沿用 §4.3。

### 4.9.1 macOS（`crates/platform/src/macos/`，`objc2` 系列，禁用 `cocoa`）

| 元件 | 做法 | 來源 |
|---|---|---|
| `clipboard.rs` | `pw-clip` 執行緒每 `POLL_INTERVAL_MS` 讀 `NSPasteboard.changeCount`；**整個迭代**包在 `autoreleasepool` 裡。有密碼管理器標記就送 Empty 事件、不讀文字；否則讀 `public.utf8-plain-text` 前 `MAX_ANALYZED_CHARS` 字和來源網址 | S4 |
| `foreground.rs` | 在 main 執行緒訂閱 `NSWorkspaceDidActivateApplicationNotification`，維護前景紀錄（`FOREGROUND_HISTORY_LEN`），剪貼簿變動時取「變動前最後一個前景 App」；有 `org.chromium.source-url` 時以它為準 | S4 發現 2 |
| `paste_tap.rs` | `pw-hook` 執行緒自己的 `CFRunLoop` 跑 active `CGEventTap`（`kCGHIDEventTap`、只聽 `keyDown`/`keyUp`/`flagsChanged`）。callback 和 Windows 一樣只讀 `PasteGate` | S4 發現 4 |
| `writer.rs` | `clearContents()` 後只寫純文字；自我寫入快取記 `changeCount` | S4 |
| `input.rs` | `CGEventSourceSecondsSinceLastEventType(CombinedSessionState, AnyInputEventType)`，不需要任何權限，對應 Windows 的 `GetLastInputInfo` | 自訂 |
| 儲存 | `~/Library/Application Support/PasteWarden/`；Keychain（`keyring` crate 的 `apple-native`） | §5.1 |
| Native Messaging | manifest 寫到 S9 表格列的使用者層級路徑；IPC 用 Unix socket `~/Library/Application Support/PasteWarden/nmh.sock`，權限 `0600`，連線時用 `getpeereid` 確認是同一個使用者 | S9 |

| 常數 | 值 | 來源 |
|---|---|---|
| `POLL_INTERVAL_MS` | `250` | S4 |
| `CONCEALED_TYPES` | `org.nspasteboard.ConcealedType`、`org.nspasteboard.TransientType`、`org.nspasteboard.AutoGeneratedType` | S4（nspasteboard.org 慣例） |
| `SOURCE_URL_TYPE` | `org.chromium.source-url`，長度上限沿用 `SOURCE_URL_MAX_BYTES` | S4 發現 1 |
| `PASTE_COMBOS` | Cmd+V、Cmd+Shift+V、Cmd+Option+Shift+V（「貼上並符合樣式」） | 自訂 |
| `SELF_INPUT_TAG` | 同 Windows 的值，寫在 `kCGEventSourceUserData` | 自訂 |
| `TAP_CHECK_INTERVAL_MS` | `30_000`：檢查 `CGEventTapIsEnabled`、`AXIsProcessTrusted` | 自訂 |
| `SECURE_INPUT_CHECK` | 每次輪詢順便呼叫 `IsSecureEventInputEnabled()` | 自訂，理由見下 |

**hook 健康檢查改成問系統**：macOS 停用 tap 時會主動送 `TapDisabledByTimeout`／`TapDisabledByUserInput`（S4 發現 4），所以不需要像 Windows 那樣送 F24 探測。收到就重新啟用並計數；重新啟用後 `CGEventTapIsEnabled` 仍是 false，或 `TAP_CHECK_INTERVAL_MS` 檢查時發現 false，就設成 `Degraded(HookLost)`。使用者在執行中撤銷「輔助使用」權限時，tap 會收不到事件，所以同一個檢查也看 `AXIsProcessTrusted`，變成 false 就是 `Unavailable(NoAccessibility)`。

**macOS 版的「系統管理員視窗」是 Secure Event Input**：終端機的「安全鍵盤輸入」、密碼欄位、部分密碼管理器會開啟 Secure Input，期間**所有** event tap 都收不到按鍵。`IsSecureEventInputEnabled()` 是 true 時設成 `Degraded(SecureInput)`，告知方式和 §4.8.2 相同：系統匣圖示改變；剪貼簿判定是 `Intercept` 時跳一次通知。系統 API 查不到是哪個 App 開的，訊息只說「有 App 開啟了安全輸入」。

**權限**：active tap 需要「輔助使用」。第一次執行的導覽說明用途，按鈕用 `x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility` 打開系統設定；沒有權限時 `intercept = Unavailable(NoAccessibility)`，其他功能照常（只通知、不攔截）。S4 待決問題 2（全新 App bundle 的授權流程）在 4b 用乾淨的使用者帳號實測，結果寫回 S4。

**ad-hoc 簽章**（2026-11-25 決定：沒有預算，不買 Apple Developer ID）：TCC 用簽章辨識 App，ad-hoc 簽章每次建置都不同，所以**每次更新後「輔助使用」權限都會失效**。處理方式：
- 啟動時如果版本和上次不同，而且 `AXIsProcessTrusted` 是 false，顯示專門的訊息 `ui-desktop-status-no-accessibility-after-update`：「更新後 macOS 需要重新授權」，附授權按鈕。系統設定裡舊的項目可能還顯示為開啟，訊息要教使用者先移除舊項目再重新加入。
- Release notes 和文件網站的 macOS 安裝頁寫明這一點。和 roadmap §8 相同，只教圖形介面操作，不教任何終端機指令。

入口警告的 App 清單（Terminal、iTerm2、Ghostty、Warp 等的 bundle ID）放進 `rules/policy/macos.json`，格式和 `windows.json` 一樣；core 的 `entry::classify_with` 已經支援傳入規則。

### 4.9.2 Linux（`crates/platform/src/linux/`）

照 S5 的建議做法。4b 的範圍是**監聽、分析、清空、遮罩寫回、入口警告**，不做貼上攔截。

| 元件 | 做法 | 來源 |
|---|---|---|
| 後端選擇 | `WAYLAND_DISPLAY` 存在 → 先綁 `ext_data_control_manager_v1`，沒有再綁 `zwlr_data_control_manager_v1`；兩者都沒有但有 `DISPLAY` → XWayland＋XFixes，標成 `Degraded(XWaylandUnverified)`；純 X11 → XFixes | S5 |
| 讀取 | 先看 MIME／TARGETS，有 `x-kde-passwordManagerHint` 就不讀文字；讀 `text/plain;charset=utf-8`（X11 是 `UTF8_STRING`，含 INCR）；`flush()` 之後在 dispatch 外讀 pipe | S5 坑 4、6 |
| 寫入 | Wayland 用 data-control source，X11 成為 selection owner；只 offer 純文字；收到 `cancelled` 就結束 | S5 |
| 前景 | X11：`_NET_ACTIVE_WINDOW` 的 PropertyNotify＋XRes `QueryClientIds`；Wayland：有 `zwlr_foreign_toplevel_manager_v1` 就用，沒有就 `foreground = Unavailable(NoForeignToplevel)`，入口警告停用 | S5 |
| 儲存 | `$XDG_DATA_HOME/paste-warden/`；Secret Service（`keyring` crate 的 `sync-secret-service`）。**沒有 Secret Service 時停用登記機密**，不退回成把金鑰寫進檔案 | §5.1 |
| Native Messaging | S9 表格的 Linux 路徑；IPC 用 `$XDG_RUNTIME_DIR/paste-warden/nmh.sock`（`0600`，`SO_PEERCRED` 確認使用者） | S9 |
| 打包 | AppImage、deb（roadmap §8）；不做 Flatpak | 自訂 |

| 常數 | 值 | 來源 |
|---|---|---|
| `PASSWORD_MANAGER_HINT` | `x-kde-passwordManagerHint` | S5 |
| `DATA_CONTROL_READ_TIMEOUT_MS` | `500`：讀 pipe 的上限，逾時就放棄這一筆 | S5 坑 4；值自訂 |
| `DATA_CONTROL_READ_MAX_BYTES` | `MAX_ANALYZED_CHARS × 4`（UTF-8 最長 4 bytes），超過就停止讀取 | S5 坑 4 |
| `COSMIC_ENV_HINT` | `XDG_CURRENT_DESKTOP=COSMIC` 且沒有 data-control global → 提示設定 `COSMIC_DATA_CONTROL_ENABLED=1` | S5 |

**GNOME（Mutter 不支援 data-control）**：`watch = Unavailable(NoDataControl)`。系統匣選單提供「檢查剪貼簿」：使用者按下時 PasteWarden 視窗取得焦點，用一般的 `wl_data_device` 讀一次（Wayland 允許有焦點的 client 讀）。設定頁建議改裝瀏覽器擴充功能。GNOME Shell extension 列在 §4.10 待決問題 3。

**貼上攔截**：Wayland 沒有標準做法（S5），`intercept = Unavailable(WaylandNoIntercept)`，設定頁說明原因。X11 的 `XGrabKey` 會和使用者的其他快捷鍵工具衝突，也攔不到 Ctrl+Shift+V、中鍵和右鍵（S5），4b 不做。PRIMARY selection 見 §4.10 待決問題 2。

### 4.9.3 Android（`crates/platform/src/android/`＋`apps/desktop/src-tauri/gen/android/`）

照 S6 的建議做法。Android 不能背景讀剪貼簿（S6 發現 5），所以只做使用者主動觸發的檢查。

| 元件 | 做法 | 來源 |
|---|---|---|
| `ProcessTextActivity`（Kotlin，無 WebView） | 選取文字選單的「PasteWarden 檢查」。用 JNI 呼叫 Rust；可編輯時把選取文字換成遮罩版，唯讀時用原生對話框顯示結果 | S6 發現 1 |
| JNI 入口 | `#[unsafe(no_mangle)] extern "system" fn Java_org_pastewarden_app_ProcessTextActivity_scan`，只在 `target_os = "android"` 編譯；只回傳遮罩後的文字和訊息 ID，不回傳原文；入口初始化 `android_logger` | S6 |
| `ACTION_SEND` | 交給 `MainActivity`（Tauri UI）顯示完整報告；app 內的 `IntentPlugin.kt` 處理 `onNewIntent`，用「這個 intent 處理過了」旗標去重 | S6 |
| 前景檢查 | App 在前景時，主畫面提供「檢查剪貼簿」按鈕 | S6 發現 5 |
| 打包 | 只出 arm64 的 release APK，`applicationId` 是 `org.pastewarden.app`；`gen/android/` 進版控 | S6 |

`ProtectionStatus` 在 Android 固定是 `watch = Unavailable(AndroidNoBackground)`、`intercept = Unavailable(AndroidNoBackground)`，主畫面直接寫明。登記機密（Keystore）不在 4b 範圍，見 §4.10 待決問題 4。選單只出現在「看得到我們」的 App 裡（S6 發現 2），說明頁要列出實測過的 App。

### 4.9.4 新增的 `Reason`

| 值 | 平台 | 狀態 | 使用者看到的意思 |
|---|---|---|---|
| `SecureInput` | macOS | `intercept` Degraded | 有 App 開啟了安全輸入，暫時攔不到貼上 |
| `NoAccessibility` | macOS | `intercept` Unavailable | 沒有「輔助使用」權限，只通知、不攔截（附授權按鈕） |
| `NoAccessibilityAfterUpdate` | macOS | `intercept` Unavailable | 更新後 macOS 需要重新授權（ad-hoc 簽章，見 §4.9.1） |
| `NoDataControl` | Linux GNOME | `watch` Unavailable | 這個桌面環境不允許背景監聽，請用「檢查剪貼簿」或瀏覽器擴充功能 |
| `XWaylandUnverified` | Linux | `watch` Degraded | 只能透過 XWayland 監聽，原生 Wayland App 的複製可能收不到 |
| `CosmicDisabled` | Linux COSMIC | `watch` Unavailable | 要設定 `COSMIC_DATA_CONTROL_ENABLED=1` |
| `NoForeignToplevel` | Linux Wayland | `foreground` Unavailable | 拿不到前景視窗，入口警告停用 |
| `WaylandNoIntercept` | Linux Wayland | `intercept` Unavailable | Wayland 不允許攔截按鍵，只通知、不攔截 |
| `NoSecretService` | Linux | 登記機密停用 | 沒有 Secret Service（例如 GNOME Keyring、KWallet），無法安全保存金鑰 |
| `AndroidNoBackground` | Android | `watch`、`intercept` Unavailable | Android 不允許背景讀剪貼簿，請用選取文字選單或分享 |

### 4.9.5 優先順序與截止線

順序是 macOS → Linux → Android。**2026-12-04** 還沒完成的平台不放進發表版的 Release，文件網站的平台表標成「尚未提供」，已寫好的程式碼用 `cfg` 關掉，不刪除。

| 平台 | 必要項目（完成條件） | 可以延後 |
|---|---|---|
| macOS | 監聽、密碼管理器標記、清空與遮罩寫回、入口警告、CGEventTap 攔截（含權限導覽、tap 失效偵測、Secure Input 告知）、Keychain、Native Messaging、dmg | 錢包掉包的輸入時間 |
| Linux | ext／wlr data-control 與 X11 監聽、密碼管理器標記、清空與遮罩寫回、X11 前景與入口警告、Secret Service、AppImage | Wayland 前景、GNOME「檢查剪貼簿」、deb |
| Android | `PROCESS_TEXT`、`SEND`、前景檢查、APK | 其他 App 的選單相容性實測 |

測試：`crates/platform` 的 macOS 單元測試用私有具名 pasteboard（`NSPasteboard::pasteboardWithName`），CI 的 macOS runner 也能跑（S4）；Linux 的整合測試在 OrbStack 容器跑 sway（ext 和 wlr 都要測）和 Xvfb，標成 `#[ignore]`；Android 用模擬器加 `adb` 手動測。macOS、Linux 各自有一份手動測試清單，項目對應 §4.8.4。

## 4.10 待決問題

1. **Windows 要不要提供「以系統管理員身分執行」**：PasteWarden 自己是高 integrity 時，hook 就收得到系統管理員視窗的按鍵。代價是每次登入都要按 UAC，而且整個 App（包括 WebView）都用系統管理員權限執行，攻擊面變大。`uiAccess=true` 的 manifest 可以不用提權就繞過 UIPI，但需要簽章，而且要安裝在 Program Files，等 Phase 6 的 SignPath 有結果再說。4a 只做 §4.8 的告知。
2. **Linux PRIMARY selection**：KeePassXC 會把密碼同時放進 PRIMARY（S5 坑 7），中鍵就能貼出去。PRIMARY 每次選取文字都會變，全部送進引擎太貴。4b 先不監聽 PRIMARY，設定頁列為已知限制。
3. **GNOME Shell extension**：S5 建議的路線之一，要另外發布到 extensions.gnome.org，4b 不做。
4. **Android 登記機密**：要用 Android Keystore 保存 HMAC 金鑰，而且只能在 `PROCESS_TEXT`／`SEND` 時比對。範圍不大，但 4b 先不做。
