# ClipGuard 瀏覽器擴充功能（Chrome，Manifest V3）

桌面版守的是 Windows 剪貼簿，這個擴充功能守網頁裡的兩件事：

- **貼上機密**：在輸入框、textarea、contenteditable 貼上時，偵測到身分證、統編、信用卡、手機、API key，就先跳出提示，可以選「貼上遮罩版本」（如 `A12****789`）、「貼上原文」或「取消」。沒偵測到機密時完全不碰貼上事件。
- **Pastejacking**：你複製時，比對你選取的文字和網頁實際寫進剪貼簿的內容；被換掉、偷加指令或藏了看不見的字元就警告，並可一鍵改回你選取的文字或清空剪貼簿。

## 安裝（載入未封裝項目）

1. Chrome 開啟 `chrome://extensions`
2. 右上角打開「開發人員模式」
3. 按「載入未封裝項目」，選這個 `extension/` 資料夾
4. 需要 Chrome 111 以上（MAIN world content script）

改了程式碼後，回 `chrome://extensions` 按擴充功能卡片上的重新載入，再重新整理網頁。

## 手動測試

`test-page.html` 是測試頁，用本機 HTTP 伺服器開（擴充功能預設不在 `file://` 執行）：

```powershell
cd extension
python -m http.server 8765
# 瀏覽器開 http://localhost:8765/test-page.html
```

也可以直接開檔案，但要先在擴充功能詳細資料打開「允許存取檔案網址」。

## 偵測規則

| 種類 | 規則 | 遮罩範例 |
|---|---|---|
| 身分證／新式居留證 | 英文字母 + 1/2/8/9 + 8 碼，驗檢查碼 | `A12****789` |
| 統一編號 | 8 碼，驗檢查碼（可被 5 整除，見下方）；前面 12 字內要有「統編／統一編號／稅籍／Tax ID／VAT」 | `22****31` |
| 信用卡 | 13–19 碼，可含空白或連字號，驗 Luhn 與發卡組織開頭 | `**** **** **** 1111` |
| 手機 | `09xx-xxx-xxx`、`+886 9xx xxx xxx` | `0912***678` |
| API key | `ghp_` 等 GitHub token、`github_pat_`、`sk-ant-`、`sk-`、`AKIA`／`ASIA`、`xoxb-` 等 Slack token、`AIza` | `ghp_********abcd` |

統編檢查碼：財政部財政資訊中心〈[營利事業統一編號檢查碼邏輯修正說明](https://www.fia.gov.tw/singlehtml/3?cntId=c4d9cff38c8642ef8872774ee9987283)〉（110-12-22 公告），判斷由「可被 10 整除」改為「可被 5 整除」，112 年 4 月起釋出新號碼。新規則下隨機 8 位數大約五分之一會通過，所以這裡要求前面有關鍵字，否則日期、訂單號碼會一直誤判。

不攔截的情況：密碼欄位（本來就是拿來貼密碼的）、唯讀欄位、`<canvas>` 類編輯器（Figma 等不走 DOM 輸入）。

## 權限

`manifest.json` 沒有 `permissions` 也沒有 `host_permissions`。只用到：

| 項目 | 原因 |
|---|---|
| `content_scripts`，`matches: <all_urls>` | 貼上和複製可能發生在任何網站，必須在每個頁面注入。Chrome 會因此顯示「讀取及變更你在所有網站上的資料」 |
| `content_scripts`，`world: "MAIN"`（`main-world.js`） | 只有在網頁自己的 JS 環境裡，才能看到網頁呼叫 `setData`／`writeText` 寫了什麼（見下節） |
| `all_frames` + `match_origin_as_fallback` | 很多編輯器放在 iframe（含 `about:blank`）裡 |
| `web_accessible_resources`：`lib/secrets.js`、`lib/pastejack.js` | content script 是 classic script，要用 `import()` 載入偵測模組，Chrome 要求被 import 的檔案列在這裡。代價是網頁能探測到這兩個檔案存在（可被用來辨識你裝了 ClipGuard） |

不連網、不存任何貼上或複製的內容（只在提示框開著時放在記憶體）、沒有分析或遙測，也沒有背景 service worker。

## Pastejacking：content script 看得到什麼

Content script 預設跑在 **isolated world**：跟網頁共用 DOM，但 JS 環境分開。

| 情況 | isolated world 看得到嗎 | 做法 |
|---|---|---|
| copy 事件當下使用者選了什麼 | 看得到：`getSelection()`，input／textarea 另外讀 `selectionStart/End` | `content.js` 在 `window` capture 階段記下 |
| 網頁在 copy handler 裡 `preventDefault` + `clipboardData.setData()` | 只有事件冒泡回 `window` 時能用 `getData()` 讀到；網頁 `stopPropagation` 就讀不到 | `main-world.js` 包裝 `DataTransfer.prototype.setData` 回報，兩邊互補 |
| 網頁呼叫 `navigator.clipboard.writeText()`／`write()` | 看不到，這些呼叫發生在網頁的 JS 環境 | `main-world.js` 包裝 `Clipboard.prototype.writeText/write` |
| 網頁用 `document.execCommand('copy')` 觸發複製 | 會觸發 copy 事件，同上 | 同上 |

判斷方式（`lib/pastejack.js`）：正規化空白後完全相同 → 不警告；保留原文只在後面多加東西（新聞網站的「出處」）→ 只有加進來的東西像指令或含隱藏字元才警告；原文不見了 → 警告。沒有選取、網頁直接寫入（「複製連結」按鈕）→ 只有內容像指令（呼叫 PowerShell、`curl | sh` 等）才警告。複製後 2 秒內、使用者沒有再點擊或按鍵，網頁又呼叫 `writeText`，視為改寫這次複製。

做不到的：

- MAIN world 跟網頁共用，網頁可以繞過包裝（例如從新建的 iframe 拿原生的 `setData`），或偽造回報事件。對刻意針對 ClipGuard 的網頁，這只是提高門檻，不是保證。
- MAIN world 與 isolated world 之間沒有網頁碰不到的通道；`CustomEvent` 網頁也能派送。
- Flash、外掛、瀏覽器以外的程式改剪貼簿看不到，這部分交給桌面版。

## 測試

```powershell
cd extension
node --test
```

偵測邏輯在 `lib/*.js`（ES module，無建置步驟、無第三方套件），測試用 Node 內建的 test runner。GitHub Actions 的 `extension-test` job（`.github/workflows/extension.yml`）在改到 `extension/` 時執行。

測試和測試頁裡的「惡意指令」範例都是執行時才拼起來的字串：完整寫在檔案裡，Windows Defender 會把檔案當成 ClickFix／假 CAPTCHA 頁面隔離（開發時真的發生過）。

## 之後可以做

- **與桌面版共用規則**：目前 C#（`src/ClipGuard.Core`）和 JS 各寫一份。可以把規則（regex、權重、關鍵字）輸出成一份 JSON，兩邊都讀，再用同一組測試資料驗證兩邊結果一致；或用 native messaging 直接問桌面程式。native messaging 需要 `nativeMessaging` 權限與登錄機碼，這版先不做。
- 登記機密（檢查點 4 的 HMAC）在瀏覽器端也能比對。
- 設定頁：關閉特定種類、網站白名單（需要 `storage` 權限，只存設定不存內容）。
