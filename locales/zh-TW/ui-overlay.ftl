# In-page warning layer (packages/overlay). Single-line messages with plain variables only:
# the overlay ships a tiny parser instead of @fluent/bundle to stay under its size budget.

ui-overlay-brand = PasteWarden 剪貼簿守門員
ui-overlay-blocked-title = 已攔下網站放進剪貼簿的指令
ui-overlay-blocked-body = 這個網站想把一段指令放進你的剪貼簿。這是常見的「假驗證」手法：叫你把它貼到「執行」視窗或終端機。剪貼簿裡現在是無害的提示文字。
ui-overlay-blocked-source = 來源
ui-overlay-allow-once = 我確定安全，放行一次
ui-overlay-keep-blocked = 繼續封鎖
ui-overlay-reasons = 為什麼攔下來
ui-overlay-layers = 解混淆過程（{ $count } 層）
ui-overlay-layer = 第 { $n } 層
ui-overlay-risk = 風險 { $score } / 100
ui-overlay-paste-title = 你要貼上的內容含有機密
ui-overlay-paste-body = 偵測到 { $count } 個機密。建議貼上遮罩版。
ui-overlay-paste-masked = 貼上遮罩版
ui-overlay-paste-original = 貼上原文
ui-overlay-paste-cancel = 取消
ui-overlay-paste-hint = Enter 貼上遮罩版，Esc 取消
ui-overlay-blocked-hint = Esc 繼續封鎖
