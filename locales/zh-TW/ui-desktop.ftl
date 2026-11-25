# 桌面版的 React 介面（apps/desktop/src）：設定頁、貼上確認框、第一次執行的導覽。
# id 一律用 `ui-desktop-` 前綴。系統匣、通知這類原生文字在 ui-desktop-native.ftl。
# `$platform` 是 windows、macos 或 linux。

## 共用
ui-desktop-cancel = 取消
ui-desktop-quit = 結束 PasteWarden
ui-desktop-error-generic = 發生錯誤，請再試一次。
ui-desktop-open-accessibility = 打開「輔助使用」設定

## 保護狀態（§4.8.1）
ui-desktop-status-loading = 正在讀取保護狀態…
ui-desktop-status-title-normal = 所有保護都正常運作。
ui-desktop-status-title-degraded = 有部分保護打了折扣，原因寫在下面。
ui-desktop-status-title-failed = 有保護沒有在運作，原因寫在下面。
ui-desktop-area-watch = 監聽剪貼簿
ui-desktop-area-write = 清空、遮罩與還原
ui-desktop-area-foreground = 前景視窗（入口警告、允許清單）
ui-desktop-area-intercept = 貼上前確認
ui-desktop-state-active = 正常
ui-desktop-state-degraded = 部分受限
ui-desktop-state-unavailable = 無法使用
ui-desktop-status-unknown = 這項保護目前受到限制。

# 每個 Reason 一則（crates/platform/src/status.rs、§4.9.4）
ui-desktop-status-hook-lost = 貼上保護暫時失效：PasteWarden 收不到鍵盤事件，正在嘗試恢復。這段期間貼上機密不會先問你。
ui-desktop-status-elevated-foreground = 目前的視窗以系統管理員身分執行，PasteWarden 攔不到這裡的貼上。惡意指令仍然會在複製時清掉。
ui-desktop-status-disabled-in-settings = 你在設定裡關掉了這項保護。
ui-desktop-status-secure-input = 有 App 開啟了安全輸入（例如密碼欄位或終端機的「安全鍵盤輸入」），這段期間攔不到貼上。
ui-desktop-status-no-accessibility = 沒有「輔助使用」權限，所以只會通知、不會在貼上前攔下來。授權後就會開始攔截。
ui-desktop-status-no-accessibility-after-update = 更新後 macOS 需要重新授權。系統設定裡舊的 PasteWarden 可能還顯示為開啟，但已經失效，請先移除再重新加入。
ui-desktop-status-pasteboard-access-ask = 每次讀剪貼簿 macOS 都會詢問。請到「系統設定 → 隱私權與安全性」，把 PasteWarden 讀取剪貼簿的權限改成「永遠允許」。
ui-desktop-status-pasteboard-access-denied = 系統設定拒絕 PasteWarden 讀取剪貼簿，所以無法檢查複製的內容。可以到「系統設定 → 隱私權與安全性」，把 PasteWarden 讀取剪貼簿的權限改成「永遠允許」。
ui-desktop-status-no-data-control = 這個桌面環境（例如 GNOME）不允許程式在背景讀剪貼簿。請用系統匣的「檢查剪貼簿」，或改裝瀏覽器擴充功能。
ui-desktop-status-xwayland-unverified = 只能透過 XWayland 監聽剪貼簿，在原生 Wayland App 裡複製的內容可能收不到。
ui-desktop-status-cosmic-disabled = COSMIC 預設不開放背景讀剪貼簿，要設定環境變數 COSMIC_DATA_CONTROL_ENABLED=1 後重新登入。
ui-desktop-status-no-foreign-toplevel = 拿不到目前的前景視窗，所以入口警告和允許清單都停用。
ui-desktop-status-wayland-no-intercept = Wayland 不允許程式攔截按鍵，所以只會通知、不會在貼上前攔下來。
ui-desktop-status-x11-no-intercept = 這個版本在 X11 上不攔截貼上（會和你的快捷鍵工具衝突），只會通知。
ui-desktop-status-no-display = 找不到圖形介面（沒有 Wayland 也沒有 X11），無法監聽剪貼簿。
ui-desktop-status-no-secret-service = 找不到 Secret Service（例如 GNOME Keyring、KWallet），沒辦法安全保存金鑰，所以無法登記機密。
ui-desktop-status-android-no-background = Android 不允許程式在背景讀剪貼簿。請在選取文字的選單或「分享」裡選 PasteWarden 來檢查。
ui-desktop-status-host-failed = PasteWarden 無法連上系統，目前沒辦法保護剪貼簿。請重新啟動 PasteWarden；一直發生的話請重新開機。

## 重新授權「輔助使用」（只用圖形介面）
ui-desktop-reauth-step-1 = 按下面的按鈕，或打開「系統設定 → 隱私權與安全性 → 輔助使用」。
ui-desktop-reauth-step-2 = 在清單裡選 PasteWarden，按下方的「−」移除。開關看起來是開的也要移除。
ui-desktop-reauth-step-3 = 按「+」，到「應用程式」資料夾選 PasteWarden，再把它的開關打開。
ui-desktop-reauth-step-4 = 回到 PasteWarden，狀態幾秒內會更新。一分鐘後還沒恢復的話，從選單列圖示結束 PasteWarden 再重新打開。

## 設定頁
ui-desktop-settings-title = 剪貼簿守門員設定
ui-desktop-settings-subtitle = 所有檢查都在這台電腦上完成，剪貼簿內容不會送到任何地方。
ui-desktop-section-status = 保護狀態
ui-desktop-section-paste-guard = 貼上機密前先確認
ui-desktop-section-paste-guard-desc = 剪貼簿裡有機密時，貼上前先讓你選擇取消、貼遮罩版或貼原文。
ui-desktop-paste-guard-keyboard-only = 只攔鍵盤貼上（{ $platform ->
        [macos] Cmd+V
       *[other] Ctrl+V
    } 等）。右鍵選單、「編輯 → 貼上」和拖放都攔不到，詳見下方的「保護範圍」。
ui-desktop-paste-guard-registered = 貼上登記的機密前先確認
ui-desktop-paste-guard-registered-desc = 你在下面登記過的密碼、金鑰等。
ui-desktop-paste-guard-detected = 貼上偵測到的機密前先確認
ui-desktop-paste-guard-detected-desc = 身分證字號、信用卡號、API key、私鑰、助記詞等。
ui-desktop-section-allowlist = 允許清單
ui-desktop-section-allowlist-desc = 貼到這些 App 時不會先問你，例如密碼管理器。用程式名稱比對，必須完全相同。
ui-desktop-allowlist-label = 程式名稱
ui-desktop-allowlist-placeholder = { $platform ->
        [windows] 例如 KeePassXC.exe
        [macos] 例如 org.keepassxc.keepassxc
       *[other] 例如 keepassxc
    }
ui-desktop-allowlist-add = 加入
ui-desktop-allowlist-none = 目前沒有自訂的 App。
ui-desktop-allowlist-remove = 從允許清單移除 { $name }
ui-desktop-allowlist-empty-name = 請輸入程式名稱。
ui-desktop-section-secrets = 登記的機密
ui-desktop-section-secrets-desc = 登記你常用的密碼或金鑰，偵測規則認不出來的機密也能在貼上前提醒你。
ui-desktop-secrets-secret = 要登記的機密
ui-desktop-secrets-confirm = 再輸入一次
ui-desktop-secrets-label = 名稱（選填）
ui-desktop-secrets-label-placeholder = 例如：公司 VPN 密碼
ui-desktop-secrets-add = 登記
ui-desktop-secrets-added = 已登記。
ui-desktop-secrets-privacy = PasteWarden 只保存機密的 HMAC 雜湊，不保存原文，也無法再顯示它。名稱會以明文保存，請不要把機密寫在名稱裡。
ui-desktop-secrets-list = 已登記
ui-desktop-secrets-none = 還沒有登記任何機密。
ui-desktop-secrets-meta = { $length } 個字元 · { $date } 登記
ui-desktop-secrets-remove = 移除
ui-desktop-secrets-remove-label = 移除「{ $label }」
ui-desktop-secrets-remove-confirm = 確定移除
ui-desktop-section-scope = 保護範圍
ui-desktop-section-scope-desc = 不同的貼上方式受到的保護不一樣。這張表會跟著上方的保護狀態即時更新。
ui-desktop-scope-caption = 每種貼上方式受到哪些保護
ui-desktop-scope-col-method = 貼上方式
ui-desktop-scope-col-copy = 複製當下（清掉惡意指令）
ui-desktop-scope-col-confirm = 貼上前確認（機密）
ui-desktop-scope-cell-covered = 涵蓋
ui-desktop-scope-cell-partial = 目前受限
ui-desktop-scope-cell-not-covered = 不涵蓋
ui-desktop-scope-cell-unavailable = 目前無法使用
ui-desktop-scope-method-keyboard = 鍵盤（{ $platform ->
        [macos] Cmd+V
       *[other] Ctrl+V
    }）
ui-desktop-scope-method-context-menu = 右鍵選單的「貼上」
ui-desktop-scope-method-edit-menu = App 的「編輯 → 貼上」
ui-desktop-scope-method-drag-drop = 拖放
ui-desktop-scope-method-remote-desktop = 遠端桌面的剪貼簿同步
ui-desktop-scope-method-elevated = 貼到系統管理員視窗
ui-desktop-scope-method-secure-input = 開啟安全輸入時
ui-desktop-scope-method-middle-click = 滑鼠中鍵（PRIMARY 選取）
ui-desktop-scope-note-commands = 惡意指令在你複製的當下就被清掉，剪貼簿裡已經沒有東西，所以不論用哪種方式貼上都貼不出來。
ui-desktop-scope-note-secrets = 機密的「貼上前確認」只在鍵盤貼上時有效。用右鍵、選單或拖放貼上機密時，PasteWarden 不會先問你。
ui-desktop-scope-note-elevated = 系統管理員視窗不是完全沒有保護：惡意指令一樣在複製時清掉，入口警告也照常顯示；只有機密的貼上前確認攔不到。
ui-desktop-section-limits = { $platform ->
        [windows] Windows 上的已知限制
        [macos] macOS 上的已知限制
       *[other] Linux 上的已知限制
    }
ui-desktop-limits-windows-1 = 以系統管理員身分執行的視窗收不到 PasteWarden 的按鍵攔截，機密貼進去前不會先問你。
ui-desktop-limits-windows-2 = 複製後立刻貼上時，PasteWarden 會先等分析完成（最多 2 秒）；超過時間就不貼，並跳出提醒。
ui-desktop-limits-macos-1 = PasteWarden 每 250 毫秒檢查一次剪貼簿。複製後不到這個時間就按 Cmd+V，可能來不及攔下。
ui-desktop-limits-macos-2 = 有 App 開啟安全輸入時（例如密碼欄位、終端機的「安全鍵盤輸入」），攔不到貼上。
ui-desktop-limits-macos-3 = 每次更新 PasteWarden 後，都要到「輔助使用」移除舊的項目再重新加入，貼上攔截才會恢復。
ui-desktop-limits-linux-1 = 這個版本在 Linux 上不攔截貼上，只在複製時清掉惡意指令並提醒你。
ui-desktop-limits-linux-2 = 不監聽滑鼠中鍵用的 PRIMARY 選取。KeePassXC 等密碼管理器也會把密碼放在那裡，用中鍵就能貼出去。
ui-desktop-limits-linux-3 = GNOME 不允許程式在背景讀剪貼簿，建議改裝瀏覽器擴充功能。
ui-desktop-limits-linux-4 = Wayland 下如果拿不到前景視窗，入口警告和允許清單會停用。
ui-desktop-section-appearance = 外觀與語言
ui-desktop-section-appearance-desc = 預設跟隨系統，也可以手動指定。
ui-desktop-section-about = 關於
ui-desktop-about-version = PasteWarden 剪貼簿守門員 { $version }
ui-desktop-about-privacy = 不收集使用資料、不回報錯誤，也不會把剪貼簿內容送到網路上。

## 機密種類（確認框）
ui-desktop-kind-national-id = 身分證字號
ui-desktop-kind-resident-certificate = 居留證號
ui-desktop-kind-business-id = 統一編號
ui-desktop-kind-credit-card = 信用卡號
ui-desktop-kind-mobile-phone = 手機號碼
ui-desktop-kind-api-key = API key 或私鑰
ui-desktop-kind-registered = 你登記的機密
ui-desktop-kind-phone-number = 電話號碼
ui-desktop-kind-bank-account = 銀行帳號
ui-desktop-kind-mnemonic = 錢包助記詞
ui-desktop-kind-other = 其他機密

## 貼上確認框
ui-desktop-confirm-title = 剪貼簿裡有機密
ui-desktop-confirm-desc = 你要貼上的內容含有機密，要怎麼處理？
ui-desktop-confirm-desc-target = 你要貼到 { $target } 的內容含有機密，要怎麼處理？
ui-desktop-confirm-kinds = 偵測到
ui-desktop-confirm-preview = 遮罩版預覽
ui-desktop-confirm-keys = 按 Enter 或 Esc 會取消，什麼都不貼。
ui-desktop-confirm-cancel = 取消
ui-desktop-confirm-masked = 貼遮罩版
ui-desktop-confirm-original = 貼原文
ui-desktop-confirm-waiting = 沒有等待確認的貼上。

## 第一次執行的導覽
ui-desktop-onboarding-title = 歡迎使用剪貼簿守門員
ui-desktop-onboarding-progress = 第 { $step } 步，共 { $total } 步
ui-desktop-onboarding-next = 下一步
ui-desktop-onboarding-back = 上一步
ui-desktop-onboarding-welcome-title = 歡迎使用剪貼簿守門員
ui-desktop-onboarding-welcome-1 = PasteWarden 會在背景檢查你複製的內容。網頁騙你複製的惡意指令，會在複製的當下被清掉。
ui-desktop-onboarding-welcome-2 = 剪貼簿裡有身分證字號、信用卡號、API key 或你登記的密碼時，用鍵盤貼上前會先問你。
ui-desktop-onboarding-welcome-privacy = 所有檢查都在這台電腦上完成，剪貼簿內容不會送到任何地方。
ui-desktop-onboarding-limits-title = 先說清楚：哪些情況保護不到
ui-desktop-onboarding-limits-intro = PasteWarden 只看得到鍵盤的貼上快速鍵。右鍵選單的「貼上」、App 的「編輯 → 貼上」、拖放、遠端桌面的剪貼簿同步，它都攔不到。
ui-desktop-onboarding-limits-commands = 惡意指令不受影響：它們在複製的當下就被清掉，不論怎麼貼都貼不出來。
ui-desktop-onboarding-limits-secrets = 但機密的貼上前確認只在鍵盤貼上時有效。用其他方式貼上機密時，PasteWarden 不會先問你。
ui-desktop-onboarding-limits-later = 之後可以在設定頁的「保護範圍」再看一次這張表。
ui-desktop-onboarding-limits-ack = 我知道了
ui-desktop-onboarding-mac-accessibility-title = 允許 PasteWarden 攔截貼上
ui-desktop-onboarding-mac-accessibility-why = 要在你按 Cmd+V 時先攔下來問你，macOS 需要你在「輔助使用」裡允許 PasteWarden。PasteWarden 只看貼上的快速鍵，不記錄你打的字。
ui-desktop-onboarding-mac-accessibility-without = 不授權也可以：PasteWarden 仍然會檢查複製的內容並通知你，只是不會在貼上前攔下來。
ui-desktop-onboarding-mac-step-1 = 按下面的按鈕，打開「系統設定 → 隱私權與安全性 → 輔助使用」。
ui-desktop-onboarding-mac-step-2 = 在清單裡找到 PasteWarden，把開關打開。清單裡沒有的話，按「+」到「應用程式」資料夾選 PasteWarden。
ui-desktop-onboarding-mac-step-3 = 回到這裡，授權成功後會顯示「已取得權限」。
ui-desktop-onboarding-mac-granted = 已取得權限，貼上攔截已經啟用。
ui-desktop-onboarding-done-title = 設定完成
ui-desktop-onboarding-done-1 = PasteWarden 會常駐在系統匣（macOS 是選單列）。保護狀態、設定和登記機密都在那裡的選單裡。
ui-desktop-onboarding-done-2 = 保護打折扣的時候，圖示會改變，設定頁也會寫明原因。
ui-desktop-onboarding-finish = 開始使用
