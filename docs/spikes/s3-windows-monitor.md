# S3 Windows：剪貼簿監聽、密碼管理器標記、前景視窗、攔截 Ctrl+V、SmartScreen

- 日期：2026-11-24～25　平台：Windows 11 Home 10.0.26300（x64，Ryzen 9 5950X，實體機）　操作方式：第一輪用遠端桌面＋螢幕小鍵盤（見「發現 3」），第二輪在電腦前用實體鍵盤重測攔截、系統管理員視窗、逾時和 UWP
- 版本：Rust 1.100.0（`x86_64-pc-windows-msvc`）、`windows` 0.62.2、VS 2022 Build Tools
- Spike 程式放在暫存資料夾，不合併：單一執行檔 `pw-s3`（release 338 KB），子命令有 `monitor`、`writetest`、`mark`、`stress`、`hookbench`、`inject`、`observe`。**程式只印變動次數、格式名稱、文字長度、行程名稱和視窗標題長度，不印任何剪貼簿內容。** 寫入系統剪貼簿前會先備份，結束時還原。
- 沒有包進 Tauri，用的是純 Rust 執行檔。message-only window 和 hook 執行緒跟 Tauri 的事件迴圈怎麼共存，留給 Phase 4。

## 結論：可行，但貼上攔截有三個硬限制

| 項目 | 結果 |
|---|---|
| message-only window + `AddClipboardFormatListener` | ✅ 每次變動都收到 `WM_CLIPBOARDUPDATE`；連續寫入 3000 次一次都沒漏 |
| 讀 `CF_UNICODETEXT` | ✅ 一般變動的處理時間 0.4～1.2 ms（含查來源行程）；剪貼簿被別人占用時最長 11 ms |
| 密碼管理器標記 | ✅ `ExcludeClipboardContentFromMonitorProcessing`、`CanIncludeInClipboardHistory=0` 都偵測到，而且**完全沒讀文字**。**Chrome 內建密碼管理器**實測只標 `CanIncludeInClipboardHistory=0` 和 `CanUploadToCloudClipboard=0`，沒有 `Exclude` |
| `EmptyClipboard` 後只寫純文字 | ✅ `HTML Format`、`Rich Text Format`、Chromium 的私有格式都清掉了，只剩 `CF_UNICODETEXT` 和系統自動合成的 `CF_TEXT`／`CF_OEMTEXT`／`CF_LOCALE`。合成資料和實際從 Chrome 複製的內容各測一次 |
| `WH_KEYBOARD_LL` 吞掉貼上鍵 | ✅ 剪貼簿被判定要攔時，記事本的 **Ctrl+V、Ctrl+Shift+V、Shift+Insert** 全部吞掉（遠端操作時 Ctrl+V 8 次；實體鍵盤時三種組合各一次） |
| ⚠️ 右鍵「貼上」 | 照樣貼出來（不經過鍵盤，§5.3 本來就列在已知限制）。第一輪 spike 只 hook Ctrl+V，所以 Shift+Insert 也貼出來；第二輪加進 hook 後就擋住了 |
| ⚠️ 系統管理員視窗 | hook **完全收不到**送往系統管理員終端機的 Ctrl+V，貼上成功。遠端桌面和**實體鍵盤**結果相同，是 UIPI 造成的，和 §5.3 的已知限制一致 |
| ⚠️ **hook 逾時會 fail-open** | callback 超過約 **615 ms** 沒回傳，Windows 就不等了，**直接把按鍵交給 App**，回傳值被忽略。人工實測：callback 睡 1.2 秒時，Ctrl+V 按一次就貼上了；遠端桌面和**實體鍵盤**都一樣。實體鍵盤那次的 log 是 `Ctrl+V SWALLOWED (injected=false)`，表示 hook 收到了、也決定吞掉，是回傳值被忽略，不是漏接 |
| `SetWinEventHook(EVENT_SYSTEM_FOREGROUND)` | ✅ 拿得到 class、標題、行程名稱、是否以系統管理員執行；事件延遲 0～16 ms。UWP App 要往子視窗找，見「發現 6」 |
| 閒置成本 | 15 分鐘閒置：CPU 時間共 31 ms，working set 6.8～6.9 MB，private 1.3 MB |
| SmartScreen | ⚠️ Edge 和 Chrome 下載都**沒有**警告，但雙擊執行時**一定會跳出**藍色的「Windows 已保護您的電腦」 |
| Defender | ✅ 沒有偵測、沒有隔離（檔案有匯入 `SetWindowsHookExW`）；只有上傳樣本給雲端分析的紀錄（事件 2050） |

## 數據

### 鍵盤 hook

| 量測 | 結果 |
|---|---|
| callback 本體（查旗標、決定吞不吞） | 平均 0.09～0.41 µs，最長 14.8 µs（遠端操作 30 分鐘 514 次；實體鍵盤 4 分鐘 292 次，平均 0.27 µs、最長 12.2 µs） |
| `SendInput` → callback（同一個行程，n=2000，跑兩次） | p50 23 µs、p95 76～97 µs、p99 241～261 µs、最長 414～474 µs |
| 真實按鍵 → callback（`GetTickCount() - kb.time`） | 0 ms（解析度內） |
| 逾時門檻 | `LowLevelHooksTimeout` 沒設定時，實測約 **615 ms**（從另一個行程 `SendInput`，callback 睡 1.2 s 或 6 s，`SendInput` 都在 612～627 ms 後返回） |

逾時的細節：

- **同一個行程**送的按鍵不會逾時：callback 睡 1.2 秒，`SendInput` 就等 1.2 秒。所以同行程的 benchmark 測不出逾時，要從另一個行程送（`pw-s3 inject`）。
- 逾時後，按鍵**不會**交給排在後面的 hook：另一個行程的觀察者 hook 一次都沒看到。但按鍵會送到 App：人工測試時 hook 記錄了 `SWALLOWED`，記事本仍然貼上了。也就是說，逾時之後 hook 鏈裡其他 hook 的判斷也全部被略過。
- 連續逾時 14 次，hook **都沒有**被系統移除，之後仍然收得到事件。這和 Microsoft 文件說的「Windows 7 之後逾時會靜默移除 hook」不同。也許要更多次才會觸發，或是只在某些條件下發生，所以正式版仍然要能偵測 hook 是否失效（見建議做法）。
- callback 在跑的時候，**整台電腦的鍵盤輸入都會卡住**：另一個行程的 `SendInput` 會一直等到 callback 回傳或逾時。

### 剪貼簿

| 量測 | 結果 |
|---|---|
| 處理一次變動（開剪貼簿、列格式、讀標記和文字長度、查 owner 行程） | 一般 0.4～1.2 ms；剪貼簿被別的程式占用、要重試時 5～11 ms |
| 連續寫入 3000 次（每次間隔 1 ms，另一個行程寫入） | 收到 3009 次變動、0 次遺漏；需要重試 `OpenClipboard` 的次數共 110 次 |
| `EmptyClipboard` + 寫純文字 | 172～377 µs |
| CPU | 3000 次變動共 594 ms，**約 0.2 ms／次**；閒置時每 10 秒取樣都沒增加 |

### 記憶體（working set ／ private bytes）

| 情境 | 開始 | 結束 | 備註 |
|---|---|---|---|
| 閒置 15 分鐘 | 6.41 ／ 1.27 MB | 6.97 ／ 1.23 MB | CPU 31 ms |
| 人工操作 30 分鐘（43 次剪貼簿變動、95 次前景切換、514 次按鍵事件） | 6.80 ／ 1.35 MB | 7.14 ／ 1.23 MB | CPU 47 ms |
| 連續寫入 3000 次 | 6.40 ／ 1.26 MB | 6.98 ／ 1.27 MB | 之後 50 秒都沒成長；handles 101 → 105、GDI 0、USER 物件 4 |

沒有發現洩漏。Windows 這邊沒有類似 macOS `autoreleasepool` 的陷阱，但每個 `GlobalLock` 都要配一個 `GlobalUnlock`，`OpenProcess` 拿到的 handle 也要關掉。

## 發現

1. **一律用自己的 hwnd 開剪貼簿，不要用 `OpenClipboard(NULL)`**。兩個行程都用 NULL owner 互搶時，1500 次寫入中有 37 次 `CloseClipboard` 回報「執行緒沒有開啟剪貼簿」（`0x8007058A`），最後的還原也失敗，剪貼簿被清空。改用自己的 message-only window 之後是 0 次。另外，`OpenClipboard(NULL)` 之後再 `EmptyClipboard` 會把 owner 設成 NULL，接著 `SetClipboardData` 就會失敗（Microsoft 文件有寫）。spike 一開始就是踩到這個，第一次的 `mark` 在還原前 panic，把使用者的剪貼簿蓋掉了。正式版要用 Drop guard 保證還原，而且不能在持有剪貼簿時 panic。
2. **Windows 版 Chrome 也會附上來源網址**：從 Chrome 複製網頁內容時，格式有 `Chromium internal source URL`、`Chromium internal source RFH token`，`HTML Format` 的標頭也有 `SourceURL:`。和 macOS 的 `org.chromium.source-url` 一樣，可以拿來做 `Context.source`。Edge 應該一樣（同樣是 Chromium），但沒有單獨測；Firefox 沒測。
3. **按鍵可能都帶 `LLKHF_INJECTED`**：第一輪透過遠端桌面和螢幕小鍵盤操作，**所有** Ctrl+V 都帶 injected 旗標。第二輪改用實體鍵盤，292 個按鍵**全部**是 `injected=false`。所以使用者用遠端桌面、螢幕小鍵盤或按鍵改寫工具時，所有按鍵都會是 injected。正式版**不能**用「injected 就放行」來避免攔到自己送的按鍵，只能比對自己的 `dwExtraInfo` 標記（§5.3 現在的做法就是這樣，是對的）。
4. **一次複製會觸發好幾次 `WM_CLIPBOARDUPDATE`**：
   - 同一個序號（`GetClipboardSequenceNumber`）會收到兩次通知，例如 seq 45475、45509 各收到兩次。
   - 在 Claude Code（跑在 Tabby 裡）選取文字時，Tabby 先寫一次，接著有一個短命的 `powershell.exe -NoProfile -NonInteractive -Command … Set-Clipboard -Value ([Console]::In.ReadToEnd())` 把同一段文字再寫 2～3 次（格式多了 `DataObject`、`Ole Private Data`）。從 Windows PowerShell 事件記錄（事件 400）查到這個命令列，推測是 Claude Code 的「選取即複製」，父行程沒有抓到。
   - 所以要用「序號」和「內容雜湊」兩層去重，不然同一段內容會分析、通知好幾次。而且很多合法工具都用 powershell 寫剪貼簿，「owner 是 powershell」不能當成可疑訊號。
5. **剪貼簿 owner 比「最後的前景視窗」更能代表來源**：從 Chrome 複製時，`GetClipboardOwner` 正確指向 `chrome.exe`，但這時最後的前景視窗常常是 `explorer.exe`（class `XamlExplorerHostIslandWindow`，也就是 Alt+Tab 的畫面）。不過 owner 也可能是 NULL（例如用 `OpenClipboard(NULL)` 寫入的程式），或是代寫的輔助行程（發現 4 的 powershell）。
6. **前景視窗的坑**：
   - UWP App（「設定」、「計算機」）的前景視窗是 `ApplicationFrameHost.exe`（class `ApplicationFrameWindow`）。第一輪用 `FindWindowExW` 找 `Windows.UI.Core.CoreWindow` 子視窗，**兩次都找不到**。第二輪改用 `EnumChildWindows` 找 PID 跟 frame host 不同的子視窗，7 次裡有 6 次正確解析成 `SystemSettings.exe`、`CalculatorApp.exe`。唯一失敗的是計算機剛啟動那一次，300 ms 後再查還是找不到，推測 App 還在啟動畫面；下一次切回來就抓到了。正式版要在找不到時先回報「未知」，等下一次前景事件再更新。
   - Windows Hello 的認證視窗（class `Credential Dialog Xaml Host`）有一次**連 `PROCESS_QUERY_LIMITED_INFORMATION` 都被拒絕**，拿不到行程名稱；另一次是 `CredentialUIBroker.exe`。§5.3 的允許清單同時比對 class 是對的。
   - 系統管理員行程用 `PROCESS_QUERY_LIMITED_INFORMATION` 拿得到名稱，token 也查得到是否以系統管理員執行（`WindowsTerminal.exe[admin]`）。
7. **`CanUploadToCloudClipboard=0` 單獨出現時不代表是機密**：spike 只把 `Exclude` 和 `CanIncludeInClipboardHistory=0` 當成密碼管理器標記，只標「不上傳雲端」的照常分析。Chrome 密碼管理器同時標了 history 和 cloud，所以不受影響。
8. **SmartScreen 與 MOTW**：
   - 即使從 `http://127.0.0.1` 下載，Edge 也會加上 `Zone.Identifier`（`ZoneId=3`、`HostUrl=…`），所以本機伺服器就能模擬使用者下載。
   - Edge、Chrome 的下載列都**沒有**「不常下載」之類的警告（可能因為來源是 localhost；從真正的網站下載時可能不同，沒有測）。
   - 雙擊執行一定會跳出 SmartScreen 藍色視窗（未簽章、沒有信譽）。按「其他資訊」→「仍要執行」之後，**Windows 會移除 `Zone.Identifier`**，之後再執行就不會再跳。
   - Defender：即時保護、雲端保護（MAPS 進階）、自動提交樣本都開著，**沒有偵測到任何威脅**。下載時有兩次雲端查詢（事件 2010），用 Chrome 下載的那份被上傳給雲端分析（事件 2050）。Smart App Control 是關閉的，開著的話可能直接擋下未簽章的程式（沒測）。

## 建議做法（Phase 4）

- `crates/platform/src/windows/`：
  - `ClipboardMonitor`：獨立執行緒，自己的 message-only window 加 `AddClipboardFormatListener`。所有 `OpenClipboard` 都傳這個 hwnd，失敗就短暫重試（spike 用 5 ms × 20 次），並用 guard 保證 `CloseClipboard`。先列格式：有 `ExcludeClipboardContentFromMonitorProcessing`，或 `CanIncludeInClipboardHistory` 的值是 0，就略過、不讀文字。再讀 `CF_UNICODETEXT`、`Chromium internal source URL`（或 `HTML Format` 的 `SourceURL`），以及 `GetClipboardOwner` 對應的行程。用序號和內容雜湊去重。
  - `ActiveWindowProvider`：`SetWinEventHook(EVENT_SYSTEM_FOREGROUND, WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS)`，維護最近的前景紀錄；UWP 要往子視窗找真正的 App。**來源判斷優先順序**：剪貼簿 metadata（來源網址）→ 剪貼簿 owner → 變動前最後一個前景視窗。
  - `PasteInterceptor`：**專用的 hook 執行緒**，只跑訊息迴圈，提高執行緒優先權。callback 只讀 atomic 旗標（「目前剪貼簿序號＋判定」），不配置記憶體、不拿鎖、不做 IO。log 交給別的執行緒（spike 用 channel）。§5.3 的「序號跟摘要不同 → 先擋，分析完再決定」**一定要先吞掉、之後再送回**，不能在 callback 裡等分析結果，因為超過約 600 ms 就會 fail-open。
  - **偵測 hook 失效**：定期送一個帶標記的無害按鍵（spike 用 F24 加 `dwExtraInfo` 標記，並在 callback 裡吞掉），收不到就重新安裝 hook，並在 UI 顯示「貼上保護暫時失效」。
  - `ClipboardWriter`：用自己的 hwnd 開剪貼簿，`EmptyClipboard` 後只寫 `CF_UNICODETEXT`，再加上 `CanIncludeInClipboardHistory=0`（§5.3 已經要求）。寫入的序號和雜湊記進自我寫入防迴圈的快取。
- **貼上路徑**：hook 要涵蓋 Ctrl+V、Ctrl+Shift+V、Shift+Insert（§5.3 已列，三種都實測擋得住）。spike 自己追蹤 Ctrl、Shift 的按下狀態，並且在吞掉按下事件時，也吞掉同一個鍵的放開事件。右鍵「貼上」、系統管理員視窗照 §5.3 列為已知限制，在設定頁說清楚。
- **測試**：`hookbench` 的做法可以做成整合測試（同行程 `SendInput` 帶標記的 F24，量延遲、驗證吞鍵），但逾時行為要從另一個行程送才測得到。CI 的 Windows runner 有沒有互動式桌面、能不能裝 LL hook，要另外確認。
- **發佈**：要簽章，不然每個使用者第一次執行都會看到 SmartScreen 警告。依目前所知（沒有實測）：EV 憑證已經不能立刻取得 SmartScreen 信譽，要靠下載量累積；Microsoft 的 Azure Trusted Signing 是比較便宜的選項，要確認個人或學生團隊能不能申請。現在 Defender 沒有誤判，**不需要送 Microsoft 申訴**；以後如果被誤判，再用 Microsoft Security Intelligence 的檔案提交頁面申訴。Tauri 產生的 MSI／NSIS 安裝檔也會遇到一樣的 SmartScreen 警告。

## 待決問題

1. **hook 被系統移除的條件**：文件說逾時會被靜默移除，但連續 14 次逾時都沒發生。要不要做「定期探測、自動重裝」？spike 建議要做，成本很低。
2. **從真正網站下載時的瀏覽器下載警告**，以及開啟 Smart App Control 時未簽章程式的反應（這台機器關閉）。發表前要用正式的發佈網址再測一次。
3. **簽章方案**：Azure Trusted Signing 的申請資格與費用，或接受第一次執行時的 SmartScreen 警告，並在下載頁說明怎麼按「仍要執行」。
4. **Tauri 整合**：message-only window 和 hook 執行緒放在 Tauri 的哪個執行緒、怎麼跟 Tauri 的事件迴圈共存（Phase 4）。

已經解決（第二輪，實體鍵盤）：Shift+Insert、Ctrl+Shift+V 擋得住；UWP 用 `EnumChildWindows` 解析得到；實體按鍵不帶 injected 旗標；系統管理員視窗攔不到、逾時會 fail-open，這兩項和遠端操作時的結果相同。
