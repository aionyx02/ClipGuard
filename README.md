# ClipGuard

Windows 剪貼簿守門員：把剪貼簿當成信任邊界，同時防守兩個方向。

- **進來的威脅**：假人機驗證騙你按 Win+R 貼上指令（ClickFix / FileFix）、Pastejacking、隱藏字元、錢包地址被掉包
- **出去的威脅**：身分證、統編、信用卡、手機、API key 和你自己登記的機密被貼出去

## 功能

### 桌面程式（系統匣）

| 功能 | 說明 | 動作 |
|---|---|---|
| 🛑 **假驗證指令攔截** | 偵測會叫起 PowerShell、mshta、cmd 等程式的指令，同時帶有隱藏視窗、編碼、誘餌註解、空白填充等詐騙特徵時攔截 | 清空剪貼簿並跳紅色通知，點擊通知可還原 |
| ⚠️ **可疑指令提醒** | 會執行程式、但沒有詐騙特徵的指令（例如官方安裝指令） | 黃色提醒，不清空 |
| 💬 **白話說明** | 用白話說明指令會做什麼，並把 `-enc` 編碼的內容解出來 | 顯示在通知裡 |
| 🚪 **執行入口再警告** | 剪貼簿有危險指令時，打開 Win+R、檔案總管、檔案對話框或終端機會再警告一次 | 每個視窗只提醒一次 |
| 🔐 **個資偵測** | 身分證／居留證、統一編號、信用卡號碼都會驗檢查碼，另外偵測手機號碼 | 遮罩後通知（`A12****789`） |
| 🔑 **API key 偵測** | GitHub、OpenAI / Anthropic、AWS、Stripe、Slack、Google、GitLab、npm、PEM 私鑰 | 遮罩後通知 |
| 📝 **登記機密** | 在系統匣選單登記自己的密碼或號碼，只存 HMAC，不存原文 | 複製到時通知 |
| ✋ **貼上前確認** | 剪貼簿含登記的機密時，在 Ctrl+V／Shift+Insert 的當下擋住，跳出搶焦點的確認框；手快按下的 Enter 只會取消。個資與 API key 可以在系統匣選單另外打開；密碼管理器和允許清單內的程式照常貼上 | 取消、貼遮罩版或貼原文（要明確點選） |
| 👻 **隱藏字元** | 零寬字元、Bidi 控制字元、混進英文的西里爾或希臘字母、指令結尾的換行 | 提醒 |
| 💰 **錢包掉包** | 複製的 BTC / ETH / TRON 地址在短時間內被換成另一個地址 | 紅色通知 |

### 瀏覽器插件（`extension/`，Chrome MV3）

| 功能 | 說明 |
|---|---|
| 🙈 **貼上遮罩** | 在網頁上貼上機密時，可以選擇貼遮罩版、貼原文或取消；沒有機密時完全不介入 |
| 🪝 **Pastejacking 偵測** | 網頁偷偷把你複製的內容換成別的東西（例如指令）時警告 |

安裝方式見 [`extension/README.md`](extension/README.md)。

> 每個功能具體的判斷規則、取捨和已知缺口，見 **[判斷準則 `docs/detection-rules.md`](docs/detection-rules.md)**。修改偵測行為或 review PR 時，以這份文件為準。

## 已知限制

- 貼上前確認只攔**鍵盤**貼上（Ctrl+V、Ctrl+Shift+V、Shift+Insert）：右鍵選單的「貼上」、拖放攔不到；以系統管理員權限執行的視窗也攔不到。預設只攔登記的機密，個資與 API key 要自己打開（#25）。
- 貼上前確認用的是低階鍵盤 hook，防毒軟體可能視為可疑；設定上用不到時（沒有登記機密、也沒打開個資攔截）不會安裝。
- 指令偵測可以被長度填充和完整路徑繞過（#19）。
- 個資規則目前只支援台灣（#27）。

完整清單見 [issues](https://github.com/aionyx02/ClipGuard/issues)。

## 結構

```
src/ClipGuard.Core   純邏輯（偵測規則），不含 UI 和 Win32，可以單元測試
src/ClipGuard.App    WinForms 系統匣程式：監聽剪貼簿、前景視窗，負責通知與對話框
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

## 開發流程

`feature/*` → PR 到 `dev` → PR 到 `main`。`main` 只接受來自 `dev` 的 PR，兩個分支都要通過 CI（`build-test`、`only-from-dev`）。

## 隱私

- 剪貼簿內容不寫檔、不記錄、不連網。被攔截的原文只留在記憶體裡，用來還原。
- 貼上前確認只記「這份剪貼簿含哪些機密」的種類和遮罩字串，不記原文；設定存在 `%LOCALAPPDATA%\ClipGuard\paste-guard.json`，只有開關和允許清單。不記錄任何按鍵。
- 登記的機密只存「長度 + HMAC-SHA256」，位置在 `%LOCALAPPDATA%\ClipGuard\secrets.json`。HMAC 金鑰是隨機產生的 256 位元，用 DPAPI（目前的 Windows 使用者）保護，存在同一個目錄的 `key.bin`。
- 不用單純的 SHA-256，因為身分證、手機這類號碼只有約 1e8–1e9 種組合，雜湊值可以被暴力反推。
