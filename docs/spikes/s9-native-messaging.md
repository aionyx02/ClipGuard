# S9 Native Messaging（macOS 部分；Windows 待補）

- 日期：2026-11-24　平台：macOS（Darwin 27.2，Apple Silicon），headless
- 版本：Playwright 1.65.1 內建的 Chromium 159（Google Chrome for Testing）、Firefox 159.0；Rust 1.100.0（host 只用 `serde_json`）
- Spike 程式放在暫存資料夾，不合併：Rust host（stdin/stdout、4-byte native-endian 長度前綴 + JSON）、Chrome MV3 擴充功能（manifest 的 `key` 固定 ID，好／壞兩組）、Firefox MV3 擴充功能（`browser_specific_settings.gecko.id` 為 `pw-spike@example.invalid`／`pw-wrong@example.invalid`）。Chromium 用 `--load-extension`；Firefox 照 S2 的做法用 RDP `installTemporaryAddon`，再由 content script 轉給 background 執行測試。
- **沒有碰使用者的瀏覽器**。Chromium 的 manifest 放在 Playwright 自訂的 `--user-data-dir` 裡面。Firefox 只能用真正的使用者路徑，這台電腦沒裝 Firefox，該目錄原本也不存在，測完已整個刪除並確認。

## 結論：可行

1. 兩個瀏覽器都能雙向傳訊息：`connectNative` 長連線和 `sendNativeMessage` 單次呼叫都實測成功，host 也能主動推送（push）。
2. **擴充功能 ID 的白名單由瀏覽器強制執行**：ID 不在 `allowed_origins`／`allowed_extensions` 裡，host 根本不會被啟動。
3. host 可以從 argv 知道呼叫者：Chrome 是 `argv[1] = "chrome-extension://<id>/"`，Firefox 是 `argv[1] = manifest 路徑`、`argv[2] = extension id`。host 自己再比對一次白名單（深度防禦）實測有效。但 argv 任何本機程式都能偽造，所以 host **不能提供任何讀取機密的功能**（見 T16）。
4. 只裝擴充功能、沒有 host 時，錯誤會走 promise reject／`onDisconnect`，`catch` 起來就能安靜降級，不會跳出 UI 或拋出未處理的例外。
5. 延遲很低：長連線來回 1 KB 約 0.2 ms；單次呼叫每次都要啟動新的 process，約 3.5–5.5 ms。

## 安裝位置（實測：Chromium 的 user-data-dir、Firefox 的使用者路徑；其餘查文件）

| 瀏覽器 | macOS 使用者層級 | Linux 使用者層級 | Windows（**待在 Windows 驗證**） |
|---|---|---|---|
| Chrome | `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/<name>.json` | `~/.config/google-chrome/NativeMessagingHosts/` | `HKCU\Software\Google\Chrome\NativeMessagingHosts\<name>`，預設值 = manifest 的絕對路徑 |
| Chromium | `~/Library/Application Support/Chromium/NativeMessagingHosts/` | `~/.config/chromium/NativeMessagingHosts/` | `HKCU\Software\Chromium\NativeMessagingHosts\<name>` |
| Edge | `~/Library/Application Support/Microsoft Edge/NativeMessagingHosts/` | `~/.config/microsoft-edge/NativeMessagingHosts/` | `HKCU\Software\Microsoft\Edge\NativeMessagingHosts\<name>` |
| Brave | `~/Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts/` | `~/.config/BraveSoftware/Brave-Browser/NativeMessagingHosts/` | 沿用 Chrome 的 key（待驗證） |
| Firefox | `~/Library/Application Support/Mozilla/NativeMessagingHosts/<name>.json` | `~/.mozilla/native-messaging-hosts/` | `HKCU\Software\Mozilla\NativeMessagingHosts\<name>`，預設值 = manifest 的絕對路徑 |

- 系統層級（需要 root／admin，我們**不用**）：macOS `/Library/Google/Chrome/NativeMessagingHosts/`、`/Library/Application Support/Mozilla/NativeMessagingHosts/`（這台電腦上已有 Apple 密碼與 Chrome Remote Desktop 的 manifest）；Linux `/etc/opt/chrome/native-messaging-hosts/`、`/usr/lib/mozilla/native-messaging-hosts/`。
- **Chromium 的使用者層級路徑就是 `<user-data-dir>/NativeMessagingHosts`，而且會跟著 `--user-data-dir` 走**（實測：manifest 只放在暫存 profile 裡就能連上）。所以 E2E 測試可以完全不碰共用路徑。
- **Firefox 不吃 `HOME`**：把 `HOME` 換成假目錄後回報 `No such native application`，macOS 上是用系統 API 找 Application Support。Firefox 的 E2E 只能寫真的使用者路徑，測完要清掉。
- manifest 檔名必須等於 `name`（`org.pastewarden.spike`），`path` 要用絕對路徑。host 啟動時的 cwd 是 host 執行檔所在的資料夾（兩個瀏覽器都是），parent process 是瀏覽器主程式。
- Linux 的 snap／Flatpak 版 Firefox 預設不能啟動 sandbox 外面的 host，要走 portal，**待 S5 或 Phase 4 驗證**。

**Tauri 安裝程式要做的事**：依照偵測到的瀏覽器，寫入上表的使用者層級 manifest（Windows 是寫 manifest 檔再加 registry key），解除安裝時全部刪掉。`path` 指向 app bundle 裡的 host 執行檔（macOS：`PasteWarden.app/Contents/MacOS/paste-warden-nmh`）。Chrome、Edge 從商店安裝後 extension ID 不一樣，`allowed_origins` 兩個都要列；Firefox 用 AMO 固定的 gecko id。`allowed_origins` 不能用萬用字元。

## 實測結果

| 情境 | Chromium | Firefox |
|---|---|---|
| 長連線，同一個 port 多次呼叫 | ✅ 同一個 pid | ✅ 同一個 pid |
| host 主動推送 3 則再回覆 | ✅ 4 則照順序收到 | ✅ |
| `sendNativeMessage` 時 host 送出多則 | 只拿到第一則，host 接著被關掉 | 同左 |
| host → 擴充功能 1,048,570 B | ✅ | ✅ |
| host → 擴充功能 > 1 MiB（1,048,590 B） | ❌ `Error when communicating with the native messaging host.` | ❌ `Native application tried to send a message of 1048590 bytes, which exceeds the limit of 1048576 bytes.` |
| 擴充功能 → host 2 MiB（host 自己限制 1 MiB 後 exit 4） | 斷線，`Error when communicating…` | 斷線，`port.error` 是 null |
| host `exit(0)`、`exit(7)`、panic | port：`Native host has exited.`；單次：同一句 | port：斷線但 **`port.error` 是 null**；單次：`An unexpected error occurred` |
| host 寫出沒有長度前綴的垃圾 | `Error when communicating…` | 被當成長度：`…544501614 bytes, which exceeds the limit…` |
| host 寫 stderr | 不影響，訊息照常（Chrome 會轉到自己的 stderr） | 同左 |
| 擴充功能 `port.disconnect()` | host 讀到 EOF，正常結束 | 同左 |
| 從 Chrome service worker 呼叫 | ✅ 3.8 ms | — |
| **沒有 manifest（只裝擴充功能）** | `Specified native messaging host not found.` | `No such native application org.pastewarden.spike` |
| manifest 在，但 host 執行檔不見 | `Specified native messaging host not found.` | `An unexpected error occurred` |
| **另一個 extension ID（不在白名單）** | `Access to the specified native messaging host is forbidden.`，host 沒被啟動 | `No such native application …`（和沒安裝一樣），host 沒被啟動 |
| 另一個 ID 被放進白名單，host 自己拒絕（exit 3） | `Native host has exited.` | port 斷線，`port.error` 是 null |
| 擴充功能沒宣告 `nativeMessaging` 權限 | `chrome.runtime.connectNative` 是 `undefined` | 未測（推論相同） |

host 看到的 argv（實測）：
- Chrome：`[<host path>, "chrome-extension://pfoeleofbpiicppadpiimgfemhcpjnfc/"]`。文件說 Windows 上還會多一個 `--parent-window=<HWND>`，**待驗證**。
- Firefox：`[<host path>, "/Users/…/Mozilla/NativeMessagingHosts/org.pastewarden.spike.json", "pw-spike@example.invalid"]`

## 延遲（1 KB echo，單位 ms）

| 路徑 | Chromium 中位數／p95 | Firefox 中位數／p95 |
|---|---|---|
| 長連線，熱的 port（200 次） | 0.2 / 0.3 | 0.22 / 0.76 |
| 開新 port 到收到第一則回覆（含 spawn，20 次） | 5.0 / 6.1 | 6.2 / 7.2 |
| `sendNativeMessage` 單次（50 次） | 3.5 / 4.1 | 5.5 / 12.9 |

Firefox 的數字是 background 裡量的，沒有經過 content script 橋接。host 是 600 KB 的 release binary；換成 Tauri 主程式這種大型執行檔，spawn 時間會變長，所以 host 要是**獨立的小 binary**。

## 遇到的坑

- Firefox 的 port 在 host 當掉時不會給錯誤（`port.error` 是 null），和正常關閉分不出來。斷線原因要靠應用層判斷：沒收到 `bye` 就斷線，一律視為異常。
- Firefox 對「ID 不在白名單」和「沒安裝」回同一個錯誤，擴充功能端分不出是哪一種。Chrome 會明確說 forbidden。
- Playwright 的 Firefox 不能 `goto` `moz-extension://` 頁面，也抓不到擴充功能自己開的分頁，所以要用 content script 加 http 頁面橋接（和 S2 一樣）。
- Playwright 的 Chromium 不管 `--user-data-dir` 怎麼設，都會更新 `~/Library/Application Support/Google/Chrome for Testing/Crashpad/settings.dat`（這個資料夾 S2 之前就有了，不是本次建立的）。
- 長度前綴是 native-endian。目前所有平台都是 little-endian，但程式裡照規格寫 `to_ne_bytes`。Windows 的 stdout 要確認是 binary mode（Rust std 不會轉換換行，**待驗證**）。

## Phase 4 建議設計

**架構**：`paste-warden-nmh` 是獨立的小 binary（`crates/platform` 內），只負責轉送。需要桌面端狀態時，透過本機 IPC（Unix socket／named pipe，權限只給本人）去問正在執行的 Tauri app。app 沒在跑時，回 `desktop: "not_running"`，不要自己把 GUI 叫起來。

**訊息格式**（JSON，每則都帶版本號）：
```
→ {"v":1,"id":7,"op":"hello","ext":{"ver":"1.2.0","caps":["policy","verdict-sync"]}}
← {"v":1,"id":7,"ok":true,"host":{"ver":"1.2.0","min_ext":1,"caps":[...]},"desktop":"running"}
→ {"v":1,"id":8,"op":"verdict","kind":"secret.aws_key","severity":"high","origin_host":"example.invalid","action":"masked"}
→ {"v":1,"id":9,"op":"match_registered","hmac":"<base64 HMAC-SHA256>"}   // 擴充功能先算好 HMAC，不送原文
← {"v":1,"id":9,"ok":true,"matched":true,"label_id":"reg-3"}
← {"v":1,"push":"policy","policy":{...}}                                   // 桌面端主動推送設定
```
- `op` 只有固定幾種：`hello`、`policy.get`、`verdict`（只送規則 ID、嚴重度、網域，給桌面端顯示或做統計）、`match_registered`（只送 HMAC）。未知的 `op` 回 `unknown_op`，不要斷線。
- **永遠不送**：剪貼簿或輸入框的原文、遮罩前的機密、完整 URL（只送 host）、登記機密的明文或 HMAC key。host **不提供**讀取剪貼簿或讀取機密的 op。理由：argv 驗證擋不住本機程式偽造，任何能啟動 host 的人都能呼叫所有 op，所以每個 op 都要假設呼叫者可能是攻擊者。
- **版本**：每則訊息帶 `v`，`hello` 交換雙方版本與 `caps`。版本差太多時，回 `{"ok":false,"err":"version"}`，擴充功能就當作沒有桌面端、自己獨立運作。
- **大小**：雙方都把單則訊息限制在 64 KiB（具名常數），遠低於瀏覽器 1 MiB 的上限。host 讀到超過上限的長度就直接結束，不要先配置記憶體。
- **驗證呼叫者**：manifest 白名單只列正式 ID（Chrome Web Store、Edge Add-ons、AMO 各一個），不列開發用 ID。host 啟動時再比對 argv 白名單，不符就 `exit` 並寫一行 log（log 裡不放訊息內容）。macOS 可以再加一層：用 `SecCode` 檢查 parent process 的簽章是不是 Google／Mozilla／Microsoft，當作加分項，不是安全邊界。
- **擴充功能端降級**：開機或安裝時用 `sendNativeMessage({op:"hello"})` 探測一次，失敗就記成 `desktop=absent`，`catch` 起來不顯示錯誤。之後只在 popup 開啟或每 N 分鐘重試，加上 backoff。功能全部以「沒有桌面端」為預設，有連上才加功能。`nativeMessaging` 考慮放在 `optional_permissions`，使用者裝了桌面版才要求（**待驗證**：兩個瀏覽器把它當 optional 時的 UX）。
- **連線方式**：需要桌面端推送設定時才用長連線（Chrome 的 `connectNative` 會讓 service worker 保持存活，要評估耗電）。偶爾查一次的用 `sendNativeMessage`（約 4–6 ms）。
- **測試**：Chromium 的 E2E 把 manifest 寫進 Playwright 的 `user-data-dir`，不碰共用路徑。Firefox 的 E2E 只在 CI 的拋棄式機器上寫 `~/Library/Application Support/Mozilla/…`（Linux 是 `~/.mozilla/native-messaging-hosts/`）。

## 待決問題

- **Windows（和 S3 一起做）**：實測 registry 位置（HKCU，Chrome／Edge／Firefox）；Chrome 是否多傳 `--parent-window`；stdout 的 binary mode；Defender／SmartScreen 對瀏覽器啟動未簽章 host 的反應。
- Linux snap／Flatpak 版 Firefox 透過 portal 啟動 host 是否可行。
- 沒有封裝的 `.app` 裡的 host 被 quarantine 標記時，瀏覽器能不能啟動它（要等 Phase 4 有簽章／公證的 build 再驗證）。
- 擴充功能和桌面端各自偵測時，警告會不會重複出現、要由誰顯示。需要在 Phase 4 規格裡定義。
