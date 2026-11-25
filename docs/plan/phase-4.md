# Phase 4：桌面版（4a Windows、4b 其他平台）

> 分支：`feature/phase-4-desktop` → PR 到 `dev`（Phase 3 的 PR 已合併）
> 依賴：core 的 `policy::{guard, entry, throttle, paste, registered, windows}`、`wallet::swap`（Phase 1）；`crates/report`（Phase 2 §2.2）。
> 參考：`docs/spikes/s3-windows-monitor.md`、`s9-native-messaging.md`（4b 另參考 S4、S5、S6）；`docs/spec/detection-rules.md` §2、§4、§5.1、§5.3、§6.2；`docs/THREAT_MODEL.md` T1、T5、T6、T15、T16

## 4.1 範圍

Phase 4 拆成兩段。**4a** 讓 Windows 和舊版 ClipGuard 的功能完全對等，再加上 Windows 的 Native Messaging；完成條件就是 roadmap 寫的「Windows 手動測試清單（含舊 #9）全部通過」。**4b** 才做 macOS、Linux、Android，照 S4、S5、S6 的建議做法，規格在 4a 完成後補進本文件。

這樣拆是因為發表現場是 Windows（roadmap 開頭），而 4a 完成時離發表日不到兩週。代價是發表時其他平台只有瀏覽器端的保護。

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
| 去重 | `(GetClipboardSequenceNumber, SHA-256(分析用的前綴))`，只記最後一組 | S3 發現 4 |
| `SELF_WRITE_SUPPRESS_MS`／`SELF_WRITE_CACHE_LEN` | `3_000`／`4` | §5.3／自訂 |
| `RUN_INITIAL_CHECK` | `true`，啟動後立刻分析現有剪貼簿 | 舊 #9 |
| `MASKED_PASTE_RESTORE_DELAY_MS` | `600` | §5.3 |
| `RESTORE_TEXT_FORMATS` | `CF_UNICODETEXT`、`Rich Text Format`、`HTML Format`、`CSV`；寫入時附加 `CanIncludeInClipboardHistory=0` | §5.3 |

來源判斷的順序是剪貼簿 metadata 的來源網址、剪貼簿 owner、變動前的前景視窗（S3 發現 5）。owner 是 `powershell` 不算可疑訊號（S3 發現 4）。

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

`restore`、`set_paste_guard { registered, detected }`、`allowlist_add`／`allowlist_remove(name)`、`register_secret { secret, confirm, label }`、`list_secrets`、`remove_secret(id)`、`set_locale`（`system`／`zh-TW`／`en`）、`set_theme`（`system`／`light`／`dark`）、`paste_choice`（`cancel`／`masked`／`original`）、`quit`。所有參數都在 Rust 端用 core 的檢查函式重新驗證；`register_secret` 收到後立刻放進 `Zeroizing`，錯誤只回欄位和訊息 ID。每個視窗的 capability 只開它需要的指令。

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
  ├─ 序號＋雜湊與上次相同，或在自我寫入快取內 → 丟掉
  ├─ 有 Exclude 標記，或 History=0 → 只送 Empty 事件，不讀文字
  └─ 讀 CF_UNICODETEXT 前 1 Mi 字＋來源網址＋owner → ClipEvent
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
每 30 s：pw-work 送出帶標記的 F24
  ├─ 1 s 內 callback 收到（並吞掉）→ 正常
  └─ 沒收到 → 重裝 hook、UI 顯示「貼上保護暫時失效」
               ├─ 下一次探測收到 → 清掉提示
               └─ 仍失敗 → 維持提示，系統匣圖示改成警示狀態
```

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
- [ ] Windows 手動測試清單全部通過。
