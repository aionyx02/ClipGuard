# ClipGuard

Windows 剪貼簿守門員：把剪貼簿當成信任邊界，同時防守兩個方向。

- **進來的威脅**：ClickFix 類假人機驗證（叫你按 Win+R 貼上指令）、Pastejacking、隱藏字元、錢包地址被換掉
- **出去的威脅**：身分證、統編、信用卡、API key 等機密被貼出去

## 進度

| 檢查點 | 內容 | 狀態 |
|---|---|---|
| 1 | 剪貼簿監聽 + ClickFix 偵測 + 系統匣通知／清空／還原 | ✅ |
| 2 | 偵測 Win+R、檔案總管網址列（FileFix）等執行入口 | ✅ |
| 3 | 個資格式偵測（含檢查碼驗證） | ⏳ |
| 4 | 登記機密：HMAC 比對，金鑰存 DPAPI | ⏳ |
| 5 | 瀏覽器插件：攔截貼上並遮罩、Pastejacking 偵測 | ⏳ |

## 結構

```
src/ClipGuard.Core   純邏輯（偵測規則），無 UI、無 Win32，可單元測試
src/ClipGuard.App    WinForms 系統匣程式：監聽剪貼簿、通知
tests/               xUnit 測試
```

## 執行

```powershell
dotnet test
dotnet run --project src/ClipGuard.App
```

## 判定規則

- **Malicious**：會呼叫可執行程式（powershell、mshta、cmd /c…），**而且**有詐騙特徵（隱藏視窗、Base64 編碼、誘餌註解、大量空白填充）。剪貼簿會被清空，原內容只留在記憶體，可從系統匣選單還原。
- **Suspicious**：只有執行特徵，例如 `powershell -c "irm https://get.scoop.sh | iex"` 這類官方安裝指令。只提醒，不清空。

## 執行入口再警告

剪貼簿裡是 Suspicious 指令，或剛攔截清空了 Malicious 指令時，只要下列視窗被叫到前景，就再跳一次通知。同一份剪貼簿內容對同一個視窗只警告一次。

| 入口 | 判斷方式（Windows 11 zh-TW 實測） |
|---|---|
| Win+R | class `#32770`、標題「執行」/ Run、行程 explorer |
| 檔案總管（FileFix） | class `CabinetWClass`、行程 explorer |
| 檔案對話框（FileFix 也用） | class `#32770`、標題「開啟」/ Open / File Upload 等 |
| 終端機 | Windows Terminal `CASCADIA_HOSTING_WINDOW_CLASS`、conhost `ConsoleWindowClass`、WezTerm 等 |

檔案總管只看前景視窗，不偵測網址列焦點：Windows 11 網址列是 XAML 元件，焦點 class（`InputSiteWindowClass`）跟檔案清單分不出來，而且等使用者按 Ctrl+L 才警告可能太晚。

啟動時會先檢查一次現有的剪貼簿。從系統匣還原的內容視為使用者已確認，不會再被清空，但開執行入口時仍會溫和提醒。

## 隱私

剪貼簿內容不寫檔、不記錄、不連網。
