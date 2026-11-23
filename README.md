<p align="center">
  <img src="assets/banner.png" alt="ClipGuard" width="100%">
</p>

# ClipGuard

Windows 剪貼簿守門員：把剪貼簿當成信任邊界，同時防守兩個方向。

- **進來的威脅**：假人機驗證騙你按 Win+R 貼上指令（ClickFix / FileFix）、Pastejacking、隱藏字元、錢包地址被掉包
- **出去的威脅**：身分證、統編、信用卡、IBAN、電話、各國身分證號、API key 和你自己登記的機密被貼出去

## 功能

### 桌面程式（系統匣）

| 功能 | 說明 | 動作 |
|---|---|---|
| 🛑 **假驗證指令攔截** | 偵測會叫起 PowerShell、mshta、cmd 等程式的指令，同時帶有隱藏視窗、編碼、誘餌註解、空白填充等詐騙特徵時攔截 | 清空剪貼簿並跳紅色通知，點擊通知可還原 |
| ⚠️ **可疑指令提醒** | 會執行程式、但沒有詐騙特徵的指令（例如官方安裝指令） | 黃色提醒，不清空 |
| 💬 **白話說明** | 用白話說明指令會做什麼，並把 `-enc` 編碼的內容解出來 | 顯示在通知裡 |
| 🚪 **執行入口再警告** | 剪貼簿有危險指令時，打開 Win+R、檔案總管、檔案對話框或終端機會再警告一次 | 每個視窗只提醒一次 |
| 🔐 **個資偵測** | 通用包一律開啟：信用卡（Luhn）、IBAN（mod-97）、`+` 開頭的國際電話。國家包依 Windows 地區設定自動開（可以在 `secret-packs.json` 手動加或關）：台灣身分證／居留證／統編／手機、中國居民身分證、日本個人番號、韓國住民登錄番號、香港身分證、新加坡 NRIC／FIN、美國 SSN。有檢查碼的都會驗；沒有檢查碼或號碼太常見的（統編、SSN、個人番號、住民登錄番號）要搭配關鍵字。全形、點號或空白分隔、中間換行的寫法也認得 | 遮罩後通知（`A12****789`） |
| 🔑 **API key 偵測** | 三層：已知前綴（GitHub、OpenAI / Anthropic、AWS、Stripe、Slack、Google、GitLab、npm、PEM 私鑰、JWT），加上從 [gitleaks](https://github.com/gitleaks/gitleaks) 轉換的近 200 種服務格式；沒有固定格式的 key 看上下文（`api_key=`、`"token": `、`Authorization: Bearer`）和亂度；再不行就自己登記。hash、UUID、git SHA、Base64 圖片不會誤報 | 遮罩後通知 |
| 📝 **登記機密** | 在系統匣選單登記自己的密碼或號碼，只存 HMAC，不存原文 | 複製到時通知 |
| ✋ **貼上前確認** | 剪貼簿含登記的機密時，在 Ctrl+V／Shift+Insert 的當下擋住，跳出搶焦點的確認框；手快按下的 Enter 只會取消。個資與 API key 可以在系統匣選單另外打開；密碼管理器和允許清單內的程式照常貼上 | 取消、貼遮罩版或貼原文（要明確點選） |
| 👻 **隱藏字元** | 零寬字元、Bidi 控制字元、混進英文的西里爾或希臘字母、指令結尾的換行 | 提醒 |
| 💰 **錢包掉包** | 複製的 BTC / ETH / TRON 地址在短時間內被換成另一個地址 | 紅色通知 |

### 瀏覽器插件（`extension/`，Chrome MV3）

| 功能 | 說明 |
|---|---|
| 🙈 **貼上遮罩** | 在網頁上貼上機密時，可以選擇貼遮罩版、貼原文或取消；沒有機密時完全不介入。API key 規則跟桌面版共用同一份規則檔 |
| 🪝 **Pastejacking 偵測** | 網頁偷偷把你複製的內容換成別的東西（例如指令）時警告 |

安裝方式見 [`extension/README.md`](extension/README.md)。

> 每個功能具體的判斷規則、取捨和已知缺口，見 **[判斷準則 `docs/detection-rules.md`](docs/detection-rules.md)**。修改偵測行為或 review PR 時，以這份文件為準。

## 已知限制

- 貼上前確認只攔**鍵盤**貼上（Ctrl+V、Ctrl+Shift+V、Shift+Insert）：右鍵選單的「貼上」、拖放攔不到；以系統管理員權限執行的視窗也攔不到。預設只攔登記的機密，個資與 API key 要自己打開（#25）。
- 貼上前確認用的是低階鍵盤 hook，防毒軟體可能視為可疑；設定上用不到時（沒有登記機密、也沒打開個資攔截）不會安裝。
- 指令偵測可以被長度填充和完整路徑繞過（#19）。
- 個資只支援上面列的國家；IBAN 要大寫，國際電話要以 `+` 開頭。SSN、日本個人番號、韓國住民登錄番號前面沒有關鍵字就不偵測（#27）。
- 誘餌註解（「我不是機器人」）認得中、英、日、韓、西、葡、法、德、俄、越等語言的常見寫法（#27）。
- 統一編號要搭配「統編」「統一編號」「VAT」「Tax ID」等關鍵字才會偵測。這是刻意的：統編的檢查碼改成「能被 5 整除」後，隨機的 8 位數字約有 1/5 會通過，單獨的 8 位數跟日期、訂單號碼分不出來。
- 超過約 100 萬字的剪貼簿只分析開頭和結尾。

完整清單見 [issues](https://github.com/aionyx02/ClipGuard/issues)。

## 結構

```
src/ClipGuard.Core   純邏輯（偵測規則），不含 UI 和 Win32，可以單元測試
src/ClipGuard.App    WinForms 系統匣程式：監聽剪貼簿、前景視窗，負責通知與對話框
rules/               桌面版與插件共用的機密規則檔（JSON），桌面版內嵌進組件
tools/               規則檔的轉換工具（gitleaks → rules/gitleaks.json、rules/ → 插件）、.resx 存取類別產生器
tests/               xUnit 測試
extension/           Chrome 插件（ES modules，用 node --test 測試）
docs/                判斷準則
```

## 執行

```powershell
dotnet test
dotnet run --project src/ClipGuard.App

cd extension; node --test
```

改了 `rules/*.json` 之後要重新產生插件用的檔案（`extension/test/rules.test.js` 會檢查）：

```powershell
node tools/build-extension-rules.mjs
```

更新 gitleaks 規則的步驟寫在 `tools/convert-gitleaks.mjs` 開頭。

## 介面語言

桌面程式和插件都支援英文與繁體中文（#27）。桌面程式跟著 Windows 的顯示語言：繁體中文（zh-TW、zh-HK、zh-MO）顯示繁中，其他語言（包括簡體中文）顯示英文。想強制指定時，用命令列參數或環境變數，命令列優先：

```powershell
dotnet run --project src/ClipGuard.App -- --lang=en
$env:CLIPGUARD_LANG = "zh-TW"; dotnet run --project src/ClipGuard.App
```

插件跟著 Chrome 的介面語言，`zh_TW` 以外一律是英文。

文字放在這些檔案，英文是預設語系，翻譯檔的 key 要跟它一樣：

| 位置 | 英文（預設） | 繁中 |
|---|---|---|
| 桌面程式的選單、通知、對話框 | `src/ClipGuard.App/Resources/Strings.resx` | `Strings.zh-TW.resx` |
| 白話說明、執行入口警告、隱藏字元與機密名稱 | `src/ClipGuard.Core/Resources/CoreStrings.resx` | `CoreStrings.zh-TW.resx` |
| 插件 | `extension/_locales/en/messages.json` | `extension/_locales/zh_TW/messages.json` |

改了 `.resx` 之後執行 `node tools/gen-resx-accessors.mjs`，重新產生強型別的存取類別（`Strings.g.cs`、`CoreStrings.g.cs`；dotnet CLI 沒有 Visual Studio 的 ResXFileCodeGenerator）。`LocalizationTests` 會檢查兩種語言的 key、`{0}` 參數、通知長度上限，以及存取類別是不是最新的。翻譯編譯成 `zh-TW/ClipGuard.App.resources.dll` 和 `zh-TW/ClipGuard.Core.resources.dll`，要跟 exe 放在一起；用 `PublishSingleFile` 發行時會直接包進 exe。

## 開發流程

`feature/*` → PR 到 `dev` → PR 到 `main`。`main` 只接受來自 `dev` 的 PR，兩個分支都要通過 CI（`build-test`、`only-from-dev`）。

## 隱私

- 剪貼簿內容不寫檔、不記錄、不連網。被攔截的原文只留在記憶體裡，用來還原。
- 貼上前確認只記「這份剪貼簿含哪些機密」的種類和遮罩字串，不記原文；設定存在 `%LOCALAPPDATA%\ClipGuard\paste-guard.json`，只有開關和允許清單。不記錄任何按鍵。
- 登記的機密只存「長度 + HMAC-SHA256」，位置在 `%LOCALAPPDATA%\ClipGuard\secrets.json`。HMAC 金鑰是隨機產生的 256 位元，用 DPAPI（目前的 Windows 使用者）保護，存在同一個目錄的 `key.bin`。
- 不用單純的 SHA-256，因為身分證、手機這類號碼只有約 1e8–1e9 種組合，雜湊值可以被暴力反推。

## 授權

本專案以 [MIT](LICENSE) 授權。

`rules/gitleaks.json`（以及由它產生的 `extension/lib/rules.generated.js`）轉換自 [gitleaks](https://github.com/gitleaks/gitleaks) 的預設規則，以 MIT License 授權，見 [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md)。
