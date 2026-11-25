# 桌面版由 Rust 產生的字串（apps/desktop/src-tauri）：系統匣選單、通知、指令錯誤。
# React 介面的字串在 ui-desktop.ftl。

## 系統匣（舊版 TrayApp 選單）
ui-desktop-tray-status-normal = 防護中
ui-desktop-tray-status-degraded = 部分防護受限
ui-desktop-tray-status-failed = 防護沒有作用
ui-desktop-tray-restore = 還原被清除的內容
ui-desktop-tray-register-secret = 登記機密…
ui-desktop-tray-manage-secrets = 管理已登記的機密…
ui-desktop-tray-paste-menu = 貼上前確認（嚴格模式）
ui-desktop-tray-strict-registered = 攔截已登記的機密
ui-desktop-tray-strict-detected = 也攔截個資與 API key
ui-desktop-tray-allowlist = 允許清單…
ui-desktop-tray-settings = 設定…
ui-desktop-tray-quit = 結束

## 通知。通知不能點擊，還原一律從系統匣選單。
ui-desktop-toast-quarantine-title = 已攔截可疑的「貼上執行」指令
ui-desktop-toast-quarantine-head = 剪貼簿已清空，正常網站不會要你按 Win+R 貼上指令。
ui-desktop-toast-quarantine-tail = 若確定安全，請從 PasteWarden 的系統匣選單還原。
ui-desktop-toast-suspicious-title = 剪貼簿裡是會執行程式的指令
ui-desktop-toast-suspicious-head = 貼上前請確認來源可信。
ui-desktop-toast-secret-title = 剪貼簿裡有機密資料
# $label：資料種類；$masked：遮罩後的值
ui-desktop-toast-secret-line = { $label } { $masked }
ui-desktop-toast-secret-more = …另有 { $count } 筆
ui-desktop-toast-secret-advice = 貼上前請確認對象與網站可信。
ui-desktop-toast-hidden-title = 剪貼簿裡有看不見或偽裝的字元
ui-desktop-toast-hidden-head = 貼上前請確認內容。
ui-desktop-toast-wallet-swap-title = 錢包地址可能被掉包
ui-desktop-toast-wallet-swap-detail = 剛複製的 { $currency ->
        [bitcoin] Bitcoin
        [ethereum] Ethereum
        [tron] Tron
        [solana] Solana
       *[xrp] XRP
    } 地址在 { $ms } 毫秒後被換成另一個地址，可能有剪貼簿劫持惡意程式。
ui-desktop-toast-wallet-swap-detail-other = 剛複製的 { $currency ->
        [bitcoin] Bitcoin
        [ethereum] Ethereum
        [tron] Tron
        [solana] Solana
       *[xrp] XRP
    } 地址在 { $ms } 毫秒後被換成另一個 { $other ->
        [bitcoin] Bitcoin
        [ethereum] Ethereum
        [tron] Tron
        [solana] Solana
       *[xrp] XRP
    } 地址，可能有剪貼簿劫持惡意程式。
ui-desktop-toast-wallet-swap-advice = 請勿貼上；假地址常與原地址頭尾相同，請逐字核對並掃毒。
ui-desktop-toast-elevated-title = PasteWarden 無法在這裡確認貼上
# $kind：ui-desktop-kind-* 訊息
ui-desktop-toast-elevated-unprotected = 這個視窗以系統管理員身分執行，PasteWarden 攔不到這裡的貼上；剪貼簿裡有{ $kind }。
ui-desktop-toast-secure-input-title = PasteWarden 暫時無法確認貼上
ui-desktop-toast-secure-input-unprotected = 有 App 開啟了安全輸入，PasteWarden 暫時攔不到貼上；剪貼簿裡有{ $kind }。
ui-desktop-toast-not-pasted-title = 沒有貼上
ui-desktop-toast-paste-timeout = 檢查剪貼簿花太久，沒有貼上，請再貼一次。
ui-desktop-toast-cannot-read = 讀不到剪貼簿內容，請重新複製一次。
ui-desktop-toast-cannot-write = 無法寫入剪貼簿，請稍後再試。
ui-desktop-toast-cannot-send = 無法把貼上送回原本的視窗，請自己再貼一次。
ui-desktop-toast-still-masked-title = 剪貼簿還是遮罩版
ui-desktop-toast-still-masked-body = 無法換回原本的內容，需要的話請重新複製一次。
ui-desktop-toast-restore-failed-title = 無法還原
ui-desktop-toast-restore-failed-body = 寫入剪貼簿失敗，內容仍保留，可以從系統匣選單再試一次。
ui-desktop-toast-settings-problem-title = PasteWarden 的設定有問題

## 指令錯誤（messageId）
ui-desktop-error-save-failed = 無法儲存設定。
ui-desktop-error-store-corrupt = 設定檔損毀，已改用預設值。
ui-desktop-error-key-unavailable = 無法從系統鑰匙圈讀取已登記機密的金鑰。
ui-desktop-error-worker-stopped = PasteWarden 沒有回應，請重新啟動。
ui-desktop-error-invalid-argument = 值不正確。
ui-desktop-error-allowlist-empty = 請輸入程式名稱。
ui-desktop-error-allowlist-too-long = 程式名稱太長。
ui-desktop-error-allowlist-duplicate = 這個程式已經在允許清單裡。
ui-desktop-error-allowlist-full = 允許清單已滿。
ui-desktop-error-allowlist-missing = 這個程式不在允許清單裡。
ui-desktop-error-label-too-long = 名稱最多 { $max } 個字。
ui-desktop-error-secrets-full = 最多只能登記 { $max } 筆機密。
ui-desktop-error-secret-missing = 這筆機密已經不存在。
ui-desktop-error-no-pending-paste = 目前沒有等待確認的貼上。
ui-desktop-error-nothing-to-restore = 沒有可以還原的內容。
ui-desktop-error-restore-failed = 無法還原內容。
ui-desktop-error-open-settings-failed = 無法開啟系統設定。
ui-desktop-error-unsupported = 這個系統不支援這項功能。
