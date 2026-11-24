# 試玩網頁（apps/web）。id 用 `ui-web-` 前綴，必須和 en/ui-web.ftl 一致。

ui-web-title = PasteWarden 試玩：貼上前先看清楚
ui-web-skip = 跳到試玩區

## 頁首與導覽
ui-web-tagline = 剪貼簿守門員
ui-web-nav-label = 主要導覽
ui-web-nav-playground = 試玩
ui-web-nav-privacy = 隱私
ui-web-nav-download = 下載
ui-web-nav-docs = 文件
ui-web-nav-github = GitHub
ui-web-prefs-label = 顯示偏好

## 主視覺
ui-web-hero-title = 貼上任何文字，看它真正會做什麼。
ui-web-hero-lead = PasteWarden 在「進來」時攔下假驗證指令、隱藏字元和被掉包的錢包地址，在「出去」時擋住身分證字號、API 金鑰和助記詞。這裡用的就是同一套偵測引擎。
ui-web-privacy-badge = 全部在你的瀏覽器裡執行，不會上傳任何資料。

## 試玩
ui-web-playground-title = 試玩
ui-web-input-label = 要檢查的文字
ui-web-input-placeholder = 貼上一段指令、訊息或助記詞…
ui-web-input-hint = 邊打邊檢查。文字只留在這個分頁：不儲存、不送出，也不會放進網址。
ui-web-clear = 清除
ui-web-chars = { $count } 個字元
ui-web-elapsed = 檢查耗時 { $ms } 毫秒
ui-web-examples-title = 試試範例
ui-web-examples-note = 所有範例都是假的、無害的：指令只會開小算盤或連到 example.invalid，號碼、金鑰和助記詞都是在這個頁面上即時產生的。
ui-web-example-clickfix = 假驗證碼（ClickFix）
ui-web-example-obfuscated = 混淆過的指令
ui-web-example-pii = 個人資料
ui-web-example-apikey = API 金鑰
ui-web-example-seed-valid = 助記詞
ui-web-example-seed-invalid = 檢查碼錯誤的助記詞
ui-web-example-clean = 一般文字
ui-web-example-clickfix-note = 假的「我不是機器人」頁面會要你按 Win+R 貼上這段。它會下載腳本並直接執行。
ui-web-example-obfuscated-note = 同樣的攻擊包了四層：^ 跳脫字元、Base64 的 -EncodedCommand、字串拼接，以及被當成指令執行的字串。看洋蔥視圖一層層剝開。
ui-web-example-pii-note = 依檢查碼算出來的身分證字號、手機號碼，以及通過 Luhn 檢查的卡號。全部是假的。
ui-web-example-apikey-note = 用固定種子產生的 GitHub 格式 token，從來沒有在其他地方存在過。
ui-web-example-seed-valid-note = 12 個 BIP-39 單字，檢查碼正確，所以可能是真錢包的復原詞。這組是從公開字串算出來的，千萬別往裡面轉錢。
ui-web-example-seed-invalid-note = 同樣的單字，只換掉最後一個。檢查碼對不上，它就只是一串英文單字，PasteWarden 不會誤報。
ui-web-example-clean-note = 一般文字應該直接放行，不打擾你。

## 結果
ui-web-results-title = 檢查結果
ui-web-loading = 正在載入偵測引擎…
ui-web-engine-error = 這個瀏覽器無法載入偵測引擎。請重新整理頁面，或改用較新的瀏覽器。
ui-web-empty-title = 還沒有要檢查的文字
ui-web-empty-body = 在上方貼上文字，或選一個範例。判定、原因和洋蔥視圖會出現在這裡。
ui-web-copy-masked = 複製遮罩後的文字
ui-web-copied = 已複製遮罩後的文字。
ui-web-copy-failed = 無法複製。請在預覽中選取文字後自行複製。

## 隱私
ui-web-privacy-title = 你可以自己驗證的隱私
ui-web-privacy-lead = 會讀剪貼簿的工具必須先贏得信任。這個頁面的設計讓你不必只聽我們說。
ui-web-privacy-local-title = 在你的裝置上執行
ui-web-privacy-local-body = 偵測引擎編譯成 WebAssembly，在這個分頁裡執行。拔掉網路線也能分析。
ui-web-privacy-none-title = 資料不會離開頁面
ui-web-privacy-none-body = 沒有分析追蹤、沒有 cookie，也不從其他網站載入字型或腳本。頁面的安全政策只允許連回自己的網址，而且載入完成後不再發出任何請求。
ui-web-privacy-open-title = 開放原始碼
ui-web-privacy-open-body = 引擎、規則和這個頁面都以 MIT 授權放在 GitHub。打開瀏覽器的開發者工具，切到「網路」分頁，打字時它會一直是空的。

## 下載
ui-web-download-title = 取得 PasteWarden
ui-web-download-lead = 瀏覽器擴充功能會在每個網站守住你的剪貼簿。安裝檔發布在 GitHub Releases，安裝說明會一步步帶你完成。
ui-web-dl-chrome = Chrome 與 Edge
ui-web-dl-chrome-desc = 擴充功能（Manifest V3）。網頁把惡意指令寫進剪貼簿的當下就攔下來。
ui-web-dl-firefox = Firefox
ui-web-dl-firefox-desc = Firefox 版的同一個擴充功能。
ui-web-dl-userscript = Userscript
ui-web-dl-userscript-desc = 給 Tampermonkey 或 Violentmonkey，適合不能安裝擴充功能的環境。
ui-web-dl-desktop = 桌面版
ui-web-dl-desktop-desc = Windows、macOS、Linux：守住整個系統的剪貼簿，不只瀏覽器。
ui-web-dl-guide = 安裝說明
ui-web-dl-soon = 即將推出
ui-web-dl-releases = GitHub 上的所有版本

## 頁尾
ui-web-footer-license = MIT 授權
ui-web-footer-engine = 引擎 { $version } · { $backend }
ui-web-backend-wasm = WebAssembly
ui-web-backend-wasm2js = JavaScript 備援
ui-web-external = （開啟 GitHub）
