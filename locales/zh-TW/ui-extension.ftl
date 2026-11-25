# 擴充功能與 userscript（apps/extension、apps/userscript）。id 一律用 `ui-ext-` 前綴。
# content script 用到的字串（提示文字、通知）只能是單行、只用一般變數。

## 攔下指令後改寫進剪貼簿的文字（貼出來也必須無害）
ui-ext-clipboard-notice = [PasteWarden 剪貼簿守門員] 已攔截：這個網站想把一段指令放進你的剪貼簿。不要把網站給的指令貼進「執行」視窗、終端機或 PowerShell。

## 頁面上不擋操作的通知
ui-ext-toast-warn-title = 貼上前先確認
ui-ext-toast-warn-body = 這個網站放進剪貼簿的內容看起來有風險。
ui-ext-toast-pastejack-title = 這個網站改了你複製的內容
ui-ext-toast-pastejack-body = 剪貼簿裡的內容和你選取的文字不一樣。
ui-ext-toast-dismiss = 關閉
ui-ext-toast-brand = 剪貼簿守門員

## 彈出視窗
ui-ext-popup-status-on = 正在保護這個頁面
ui-ext-popup-status-off = 保護已關閉
ui-ext-popup-status-paused = 已在 { $host } 暫停
ui-ext-popup-status-unavailable = 這個頁面無法使用剪貼簿守門員。瀏覽器內建頁面和擴充功能商店不允許擴充功能執行。
ui-ext-popup-page-stats = 這個頁面：攔截 { $blocked } 次、警告 { $warned } 次
ui-ext-popup-engine = 引擎：{ $backend }
ui-ext-popup-toggle-enabled = 保護
ui-ext-popup-toggle-site = 在這個網站暫停
ui-ext-popup-recent = 最近的攔截紀錄
ui-ext-popup-recent-empty = 還沒有攔截過任何東西。
ui-ext-popup-recent-note = 只記錄網站、時間、種類和遮罩後的值，不會記錄你複製的內容。
ui-ext-popup-clear = 清除
ui-ext-popup-settings = 設定
ui-ext-kind-command = 攔下指令
ui-ext-kind-warning = 警告
ui-ext-kind-pastejack = 複製內容被竄改
ui-ext-kind-secret = 貼上機密

## 設定頁
ui-ext-options-title = 剪貼簿守門員設定
ui-ext-options-privacy = 所有檢查都在你的瀏覽器裡完成，複製和貼上的內容不會送到任何地方。
ui-ext-options-protection = 保護
ui-ext-opt-enabled = 開啟保護
ui-ext-opt-enabled-desc = 一次開關下面所有檢查。
ui-ext-opt-guard-writes = 攔下網站放進剪貼簿的指令
ui-ext-opt-guard-writes-desc = 假的「驗證你是真人」頁面會幫你複製一段指令，騙你貼進「執行」視窗或終端機。剪貼簿守門員會把它換成無害的提示文字。
ui-ext-opt-guard-paste = 貼上機密前先確認
ui-ext-opt-guard-paste-desc = 在網頁貼上身分證字號、信用卡號或 API key 時，讓你選擇貼遮罩版或原文。密碼欄位不處理。
ui-ext-opt-pastejack = 偵測複製內容被竄改
ui-ext-opt-pastejack-desc = 網頁偷換或偷加你複製的文字時提醒你。
ui-ext-options-strictness = 嚴格度
ui-ext-opt-block-malicious = 攔下惡意指令
ui-ext-opt-block-malicious-desc = 關閉時只警告，指令照樣寫進剪貼簿。
ui-ext-opt-warn-suspicious = 可疑指令也警告
ui-ext-opt-warn-suspicious-desc = 不確定是惡意、但值得再看一眼的指令。
ui-ext-opt-detect-secrets = 偵測機密和個資
ui-ext-opt-detect-secrets-desc = 身分證字號、信用卡號、API key、私鑰、助記詞。
ui-ext-opt-detect-hidden = 偵測看不見的字元
ui-ext-opt-detect-hidden-desc = 零寬字元、文字方向控制字元，會讓你看到的和實際內容不一樣。
ui-ext-options-packs = 個資規則包
ui-ext-options-packs-desc = 要找哪些國家的身分證號、電話格式。信用卡、IBAN、國際電話和 API key 一律會檢查。
ui-ext-opt-packs-auto = 依瀏覽器語言自動選擇
ui-ext-pack-universal = 通用
ui-ext-pack-tw = 台灣
ui-ext-pack-cn = 中國
ui-ext-pack-jp = 日本
ui-ext-pack-kr = 韓國
ui-ext-pack-hk = 香港
ui-ext-pack-sg = 新加坡
ui-ext-pack-us = 美國
ui-ext-options-appearance = 語言與外觀
ui-ext-options-appearance-desc = 網頁上的警告跟隨系統的深淺色，不跟隨網頁本身。
ui-ext-options-allowlist = 允許清單
ui-ext-options-allowlist-desc = 剪貼簿守門員在這些網站（含子網域）完全不介入，適合你信任的內部工具。
ui-ext-allowlist-label = 網站主機名稱
ui-ext-allowlist-placeholder = intranet.example.com
ui-ext-allowlist-add = 新增
ui-ext-allowlist-remove = 移除 { $host }
ui-ext-allowlist-empty = 目前沒有網站。
ui-ext-allowlist-invalid = 請輸入主機名稱，例如 intranet.example.com。

## 設定頁：連接桌面版（Native Messaging，選用）
ui-ext-options-desktop = 桌面版
ui-ext-options-desktop-desc = 如果你也安裝了剪貼簿守門員桌面版，擴充功能可以把攔截紀錄告訴它：只有規則、網站主機名稱和處理方式，不會有你複製的內容。不連接桌面版，擴充功能也能完整運作。
ui-ext-desktop-connect = 連接桌面版
ui-ext-desktop-disconnect = 中斷連接
ui-ext-desktop-check = 重新檢查
ui-ext-desktop-denied = 瀏覽器沒有給予權限，設定沒有變更。
ui-ext-desktop-state-off = 尚未連接。
ui-ext-desktop-state-absent = 找不到桌面版。擴充功能會繼續獨立保護你，稍後再自動檢查。
ui-ext-desktop-state-not-running = 已安裝桌面版，但目前沒有執行。
ui-ext-desktop-state-incompatible = 桌面版和擴充功能的版本不相容，請兩者都更新；在那之前擴充功能會獨立運作。
ui-ext-desktop-state-running = 已連接桌面版。
