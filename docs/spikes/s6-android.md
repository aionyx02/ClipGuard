# S6 Android：`PROCESS_TEXT`、分享 intent、背景讀剪貼簿

- 日期：2026-11-24　主機：macOS（Apple Silicon）　裝置：模擬器 `Pixel_7_Pro`（Android 17 / API 37，`google_apis_playstore_ps16k` arm64，headless `-no-window`）
- 版本：Rust 1.100、`tauri` 2.12.7、`tauri-cli` 2.12.6、`wry` 0.57.3、`jni` 0.21.1、NDK r30（30.0.16248370）、AGP 9.3.1、Gradle 9.6.1、Kotlin 2.2.10、JDK 21；compileSdk / targetSdk 37、minSdk 24
- Spike 程式放在暫存資料夾，不合併：`create-tauri-app`（vanilla-ts）＋ 一個 app 內的 Kotlin plugin ＋ 一個不含 WebView 的 `ProcessTextActivity`。假的偵測：含 `PW_SPIKE` 就判定有機密，遮罩成 `PW_****`。**log 只印 action、長度、hit、readonly，不印文字內容。** 全程用 `adb`（`am start`、`input`、`uiautomator dump`、`screencap`）操作，不需要人。

## 結論：可行，但 `PROCESS_TEXT` 不能交給 Tauri 的 MainActivity

| 項目 | 結果 |
|---|---|
| 選取文字選單出現「PasteWarden 檢查」 | ✅ Chrome（網頁的 textarea 和一般文字都有）；❌ Google Messages（package visibility，見發現 2） |
| `EXTRA_PROCESS_TEXT` 取代原選取 | ✅ Chrome textarea：`aa PW_SPIKE bb` → `aa PW_**** bb`，App 冷啟動和已在執行時都成功 |
| `EXTRA_PROCESS_TEXT_READONLY` | ✅ Chrome 對不可編輯的 `<p>` 傳 `readonly=true`，App 不回傳結果，只顯示 Toast |
| `ACTION_SEND` text/plain 分享目標 | ✅ Chrome、Messages 的「分享」都能送進來，Rust 收到並判定 |
| 文字交給 Rust | ✅ 兩條路：`run_mobile_plugin`（WebView 路徑）和 JNI `extern "system"`（無 WebView 路徑） |
| 背景讀剪貼簿（Android 10 以上） | ✅ **確實被擋**：`getPrimaryClip()` 回傳 null，系統 log 出現 `Denying clipboard access to org.pastewarden.spike, application is not in focus` |
| 建置時間 | 第一次 debug（含 Gradle 下載、274 個 crate）234 秒；之後的增量建置約 5 秒；release 的 Rust 冷編譯（LTO）112 秒 |
| APK 大小（只有 arm64） | release 5.9 MB（`.so` 4.3 MB，R8 開啟）；debug 130–256 MB（保留除錯符號，不具參考價值） |
| `PROCESS_TEXT` 延遲 | JNI 掃描 70–120 µs；冷啟動時從程序啟動到回傳約 290 ms |

## Tauri v2 實際需要做的事

`tauri android init` 產生的 `src-tauri/gen/android/` 要進版控，以下修改都改在這裡。

1. **Manifest**：`ACTION_SEND` 的 intent-filter 加在 `MainActivity` 上（`android:label="PasteWarden 檢查"`，`<data android:mimeType="text/plain"/>`）。`ACTION_PROCESS_TEXT` **另外宣告一個 activity**：
   ```xml
   <activity android:name=".ProcessTextActivity" android:label="PasteWarden 檢查" android:exported="true"
       android:excludeFromRecents="true" android:noHistory="true"
       android:theme="@android:style/Theme.Translucent.NoTitleBar">
     <intent-filter><action android:name="android.intent.action.PROCESS_TEXT"/>
       <category android:name="android.intent.category.DEFAULT"/><data android:mimeType="text/plain"/></intent-filter>
   </activity>
   ```
2. **`ProcessTextActivity.kt`**（純 Android `Activity`，沒有 WebView）：`System.loadLibrary("pw_s6_lib")`，用 `external fun scanNative(text: String): String?` 呼叫 Rust；有命中且不是唯讀時呼叫 `setResult(RESULT_OK, Intent().putExtra(EXTRA_PROCESS_TEXT, masked))`，然後 `finish()`。Rust 端在同一個 cdylib 裡匯出 `#[unsafe(no_mangle)] extern "system" fn Java_org_pastewarden_spike_ProcessTextActivity_scanNative`（`jni` crate，只在 `target_os = "android"` 編譯）。正式版的 core 是純邏輯，直接呼叫即可。
   - 這裡違反了「core `forbid(unsafe_code)`」嗎？沒有：`no_mangle` 放在 app crate（或 `crates/platform/android`），core 不受影響。
3. **App 內的 Kotlin plugin**（給 WebView 路徑用，處理 SEND）：類別直接放在 `gen/android/app/src/main/java/<pkg>/IntentPlugin.kt`，加 `@TauriPlugin`，`@Command getIncoming` 讀 `activity.intent`。Rust 端用 `tauri::plugin::Builder::new("pwintent").setup(|app, api| api.register_android_plugin("org.pastewarden.spike", "IntentPlugin"))` 註冊，再由 app command 呼叫 `run_mobile_plugin("getIncoming", ())`。**不需要另外建 plugin crate。**
4. **`onNewIntent`**：`MainActivity` 是 `singleTask`，第二次 SEND 會進 `Plugin.onNewIntent`，不會重跑 `onCreate`。要自己 `activity.intent = intent`，再通知前端。Tauri 沒有現成的事件：JS 的 `addPluginListener` 會呼叫 `plugin:pwintent|registerListener`，**plugin 指令一律要過 ACL**（`webview/mod.rs` 的檢查），app 內建的 plugin 沒有 permission manifest。spike 的做法是覆寫 `Plugin.load(webView)` 保存 WebView，在 `onNewIntent` 裡 `evaluateJavascript("window.__pwOnNewIntent()")`。前端同時監聽 `visibilitychange`，所以會重複觸發，要用「這個 intent 處理過了」旗標去重。
5. 不用動 `MainActivity.kt`。

## 發現

1. **`PROCESS_TEXT` 交給 MainActivity，App 已在執行時會變成空白畫面**（最重要）。Chrome 用 `startActivityForResult` 啟動 PROCESS_TEXT。App 沒在執行時一切正常。App 已在自己的 task 執行時，Android 17 **忽略 `singleTask`**，在 Chrome 的 task 裡另外建立第二個 `MainActivity`（`dumpsys` 看到兩個 `ActivityRecord`）。Tauri 一個程序只有一個 WebView／runtime，第二個 instance 沒有 WebView，畫面全黑，也沒有任何 Rust 呼叫。改用不含 WebView 的 `ProcessTextActivity`＋JNI 後，冷啟動、已在執行、release 版都正常，而且不用等 WebView 載入，速度快很多。
2. **Package visibility 決定選單有沒有我們**：Android 11 以上，選單只會列出「呼叫端看得到」的 App。Chrome 有 `QUERY_ALL_PACKAGES`，看得到；TalkBack 是系統的 `forceQueryable`，到處都看得到；Google Messages（targetSdk 37）沒有宣告 PROCESS_TEXT 的 `<queries>`，選單只有「朗讀」。**這是對方 App 的設定，我們改不了。** 支援度要逐一實測；Messages 這類 App 只能靠 SEND 分享。
3. **SEND 在分享選單顯示成「App 名稱＋label」**：名稱是 `pw-s6`，副標題是「PasteWarden 檢查」，所以正式版的 `app_name` 本身就要清楚。Chrome 分享選取文字時會加上引號和換行（`"PW_SPIKE"\n`）；Messages 只送出選取的文字。
4. **呼叫端身分不可靠**：PROCESS_TEXT 的 `callingPackage` 有值（`com.android.chrome`），因為是 for-result。SEND 的 `callingPackage` 是 null；`activity.referrer` 在 `onNewIntent` 之後**沒有更新**，從 Messages 分享時仍然顯示 `com.android.chrome`。不能拿它當 `Context.source` 的依據。
5. **背景讀剪貼簿**：測試先寫入假的 `PW_SPIKE_CLIPTEST`（不碰真實內容），前景讀到 `len=17`；按 HOME 8 秒後讀，`hasPrimaryClip=false`、`clip=null`。Chrome 在背景想讀剪貼簿也被擋（同一段 log）。例外是**預設輸入法**：Gboard 的建議列立刻顯示 `PW_SPIKE_CLI…`。所以 Android 版做不到桌面那種剪貼簿監聽，只能做「使用者主動觸發」（PROCESS_TEXT、SEND、App 在前景時檢查），或者自己做輸入法（範圍太大，不建議）。
6. **其他雜項**：
   - `tauri android init` 會自動裝四個 Rust Android target（aarch64、armv7、i686、x86_64）。建置時用 `--target aarch64` 只編一個。
   - `run()` 沒執行時（例如冷啟動直接進 `ProcessTextActivity`）`android_logger` 不會初始化，Rust log 會消失。logger 要在 JNI 入口也初始化一次。
   - 模擬器有鎖定畫面（`wm dismiss-keyguard`），`data:` URL 不能用 intent 開啟（改用 `adb reverse` 加本機 HTTP）。Chrome 第一次開啟的畫面可以用 `/data/local/tmp/chrome-command-line` 加 `--disable-fre` 跳過，但還是會跳通知引導。
   - Chrome 網頁內容不會出現在 `uiautomator dump`（textarea 只在選取後才看得到），要靠截圖找座標。
   - release 開了 R8：`@TauriPlugin` 類別和 `external fun` 都保留下來，不需要另外寫 keep rule。

## 建議做法（行動版 Phase）

- `crates/platform/src/android/`：一個 `extern "system"` JNI 入口，呼叫 core `analyze`，只回傳遮罩後的文字和結果代碼（訊息 ID），不回傳原文。
- `ProcessTextActivity`（無 WebView）：可編輯時直接取代成遮罩後的文字；唯讀或無法遮罩時改用原生的小對話框（或 Toast）顯示結果。不要把 PROCESS_TEXT 交給 Tauri 的 WebView activity。
- SEND 交給 `MainActivity`（Tauri UI），顯示完整報告；用 `onNewIntent` 加去重處理重複觸發。
- 文件要寫明：選單只會出現在看得到我們的 App；Android 不做背景剪貼簿監聽。

## 待決問題

1. 實體手機、其他 App（Gmail、Keep、LINE、Slack）的選單支援度。模擬器的 Google Keep 映像沒有安裝，Gmail 需要登入帳號，這次都沒測。
2. 要不要實作輸入法（IME）來做到「貼上前檢查」。這是唯一能在 Android 讀剪貼簿的合法角色，但範圍和隱私責任都很大。
3. 未來 Tauri 如果支援多個 activity／WebView，PROCESS_TEXT 能不能改用 WebView UI。目前（2.12.7）不行。
