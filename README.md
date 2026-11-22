# ClipGuard

Windows 剪貼簿守門員：把剪貼簿當成信任邊界，同時防守兩個方向。

- **進來的威脅**：ClickFix 類假人機驗證（叫你按 Win+R 貼上指令）、Pastejacking、隱藏字元、錢包地址被換掉
- **出去的威脅**：身分證、統編、信用卡、API key 等機密被貼出去

## 進度

| 檢查點 | 內容 | 狀態 |
|---|---|---|
| 1 | 剪貼簿監聽 + ClickFix 偵測 + 系統匣通知／清空／還原 | ✅ |
| 2 | 偵測 Win+R、檔案總管網址列（FileFix）等執行入口 | ⏳ |
| 3 | 個資格式偵測（含檢查碼驗證） | ✅ |
| 4 | 登記機密：HMAC 比對，金鑰存 DPAPI | ✅ |
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

## 隱私

剪貼簿內容不寫檔、不記錄、不連網。

登記的機密只存「長度 + HMAC-SHA256」到 `%LOCALAPPDATA%\ClipGuard\secrets.json`，HMAC 金鑰是隨機 256 位元、以 DPAPI（目前 Windows 使用者）保護，存在同目錄的 `key.bin`。不用單純 SHA-256，是因為身分證、手機這類號碼只有約 1e8–1e9 種組合，雜湊可以被暴力反推。
