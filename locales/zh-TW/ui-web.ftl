# 試玩網頁（apps/web）。id 用 `ui-web-` 前綴，必須和 en/ui-web.ftl 一致。

ui-web-title = PasteWarden：貼上前先看清楚
ui-web-skip = 跳到主要內容
ui-web-title-play = 試玩 · PasteWarden
ui-web-back-home = 回首頁
ui-web-play-lead = 貼上任何文字，或選一個範例。邊打邊出現判定結果，文字不會離開這個分頁。

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

## 首頁示範：在頁面上畫出來的模擬攻擊（不是影片檔）。產品介面文字沿用 ui-overlay / ui-extension，
## 判定理由和引擎自己的訊息一致。
ui-web-demo-label = 示範
ui-web-demo-scenarios = 示範情境
ui-web-demo-play = 播放示範
ui-web-demo-pause = 暫停示範
ui-web-demo-chapters = 章節
ui-web-demo-xray-write = 透視：網頁寫進剪貼簿的內容
ui-web-demo-xray-clipboard = 透視：你的剪貼簿
ui-web-demo-xray-hidden = 透視：解開看不見的字元
ui-web-demo-run-title = 執行
ui-web-demo-run-hint = 輸入程式、資料夾或文件的名稱來開啟。
ui-web-demo-run-open = 開啟：
ui-web-demo-run-ok = 確定
ui-web-demo-run-cancel = 取消

ui-web-demo-tab-clickfix = 假驗證碼
ui-web-demo-tab-secrets = 貼出機密
ui-web-demo-tab-pastejack = 複製被掉包
ui-web-demo-tab-hidden = 隱藏字元

ui-web-demo-clickfix-ch-bait = 假驗證碼
ui-web-demo-clickfix-ch-catch = 攔下
ui-web-demo-clickfix-ch-safe = 什麼都沒執行
ui-web-demo-clickfix-cap-bait = 網站要你證明自己不是機器人。
ui-web-demo-clickfix-cap-copy = 勾選的同時，網頁把一段指令寫進你的剪貼簿。
ui-web-demo-clickfix-cap-catch = PasteWarden 在寫入的當下就攔下來，剪貼簿裡換成一段無害的提示文字。
ui-web-demo-clickfix-cap-safe = 就算照著步驟按 Win+R、Ctrl+V，貼上的也只是那段提示，什麼都不會執行。
ui-web-demo-clickfix-page-title = 再一步就好
ui-web-demo-clickfix-page-sub = 請確認你是真人以繼續。
ui-web-demo-clickfix-captcha = 我不是機器人
ui-web-demo-clickfix-steps = 驗證步驟
ui-web-demo-clickfix-step-1 = 打開「執行」視窗
ui-web-demo-clickfix-step-2 = 貼上驗證碼
ui-web-demo-clickfix-step-3 = 確認
ui-web-demo-clickfix-reason-1 = 呼叫 PowerShell
ui-web-demo-clickfix-reason-2 = 下載後直接執行
ui-web-demo-clickfix-reason-3 = 誘餌註解（假裝是人機驗證）

ui-web-demo-secrets-ch-copy = 複製
ui-web-demo-secrets-ch-ask = 先問你
ui-web-demo-secrets-ch-masked = 遮罩
ui-web-demo-secrets-cap-copy = 你想問 AI 怎麼修 CI，複製了一段含有存取權杖的訊息。
ui-web-demo-secrets-cap-paste = 在對話框按下 Ctrl+V……
ui-web-demo-secrets-cap-ask = PasteWarden 先攔下來問你。按 Enter 貼上的是遮罩版。
ui-web-demo-secrets-cap-masked = 送進對話的只有遮罩後的權杖，真正的權杖沒有離開你的電腦。
ui-web-demo-secrets-ai-hello = 嗨！有什麼可以幫你的？
ui-web-demo-secrets-placeholder = 傳訊息給 AI 助理……

ui-web-demo-pastejack-ch-select = 複製
ui-web-demo-pastejack-ch-swap = 被掉包
ui-web-demo-pastejack-ch-catch = 攔下
ui-web-demo-pastejack-cap-select = 在教學網站上，你選取一行安裝指令，按 Ctrl+C。
ui-web-demo-pastejack-cap-swap = 網頁偷偷寫進別的內容：多了一行下載並執行腳本的指令，結尾還帶換行。
ui-web-demo-pastejack-cap-catch = PasteWarden 在內容進到剪貼簿之前就攔下這次寫入。
ui-web-demo-pastejack-cap-safe = 貼進終端機的話，結尾的換行會讓它立刻執行。現在沒有東西可以執行了。
ui-web-demo-pastejack-page-title = 安裝 example-lib
ui-web-demo-pastejack-page-sub = 在終端機執行：
ui-web-demo-pastejack-selected = 你選取的
ui-web-demo-pastejack-written = 網頁寫進去的
ui-web-demo-pastejack-reason-1 = 下載後直接交給 shell 執行
ui-web-demo-pastejack-reason-2 = 下載後直接執行
ui-web-demo-pastejack-reason-3 = 指令結尾有換行，貼進終端機會直接執行

ui-web-demo-hidden-ch-copy = 複製
ui-web-demo-hidden-ch-warn = 警告
ui-web-demo-hidden-ch-reveal = 攤開
ui-web-demo-hidden-cap-copy = 提示詞分享網站上有一段好用的摘要提示詞，你按下「複製」。
ui-web-demo-hidden-cap-warn = PasteWarden 提醒你：這段文字裡夾帶看不見的 Unicode TAG 字元。
ui-web-demo-hidden-cap-reveal = 你看不到，AI 卻讀得到：它們叫 AI 把你的對話送到別的地方。貼給 AI 之前先確認。
ui-web-demo-hidden-page-title = 提示詞：任何文章都能摘要
ui-web-demo-hidden-page-sub = 社群分享 · 已被複製 2.4k 次
ui-web-demo-hidden-prompt = 用三個重點摘要以下文章，語氣保持中立。
ui-web-demo-hidden-copy = 複製提示詞
ui-web-demo-hidden-copied = 已複製
ui-web-demo-hidden-reason = 含 Unicode TAG 字元 { $count } 個（看不見，可能藏著給 AI 的指令）
