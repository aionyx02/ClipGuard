# Shared React components (packages/ui). Ids use the `ui-comp-` prefix so they never collide
# with the extension / web strings in ui.ftl.

## VerdictCard

ui-comp-action-allow = 安全
ui-comp-action-warn = 請注意
ui-comp-action-quarantine = 已隔離
ui-comp-action-allow-desc = 沒有發現可疑的內容。
ui-comp-action-warn-desc = 這段內容有可疑之處，使用前請再確認。
ui-comp-action-quarantine-desc = 這段內容很可能是攻擊手法，PasteWarden 已經把它攔下。
ui-comp-verdict-title = 判定結果
ui-comp-level-label = 指令判定
ui-comp-level-none = 無
ui-comp-level-suspicious = 可疑
ui-comp-level-malicious = 惡意
ui-comp-risk-label = 風險分數
ui-comp-risk-value = { $score } / 100
ui-comp-reasons-title = 判定理由
ui-comp-reasons-empty = 沒有需要說明的地方。
ui-comp-hosts-title = 指令會連到
ui-comp-hidden-title = 隱藏字元
ui-comp-wallets = 含有 { $count } 個錢包地址
ui-comp-truncated = 內容太長，只分析了開頭的部分。

## OnionTrace

ui-comp-onion-title = 洋蔥視圖
ui-comp-onion-subtitle = 一層一層剝開混淆，看看這段指令真正會做什麼。
ui-comp-onion-empty = 這段內容沒有經過混淆。
ui-comp-onion-layer = 第 { $n } 層
ui-comp-onion-next = 展開下一層
ui-comp-onion-all = 全部展開
ui-comp-onion-replay = 從頭播放
ui-comp-onion-progress = 已展開 { $shown } / { $total } 層
ui-comp-onion-announce = 第 { $n } 層，{ $text }：{ $preview }
ui-comp-onion-result = 最內層：實際內容

## SecretList / MaskPreview

ui-comp-secrets-title = 偵測到的機密
ui-comp-secrets-empty = 沒有偵測到機密。
ui-comp-secrets-note = 這裡只顯示遮罩後的值。
ui-comp-secrets-rule = 規則
ui-comp-mask-title = 遮罩預覽
ui-comp-mask-note = 貼上遮罩版時，對方只會看到這段文字。

## Preferences

ui-comp-pref-theme = 外觀
ui-comp-pref-theme-system = 跟隨系統
ui-comp-pref-theme-light = 淺色
ui-comp-pref-theme-dark = 深色
ui-comp-pref-language = 語言
ui-comp-pref-language-system = 跟隨系統
ui-comp-pref-language-zh-TW = 繁體中文
ui-comp-pref-language-en = English
