# ClipGuard：給 agent 的說明

- **偵測行為的規格**：`docs/detection-rules.md`。改規則前先讀，改完要同步更新；review PR 時照該文件 §9「Review 檢查清單」逐項核對。
- **分支流程**：從 `dev` 開 `feature/*` → PR 到 `dev`。不要直接推 `dev` 或 `main`（ruleset 會擋）。
- **Commit**：英文，conventional commits。
- **測試資料**：只用假資料。惡意指令樣本要在執行時組合，網址用 `example.invalid`；完整的惡意字串寫進檔案會被 Defender 隔離。
- **驗證**：`dotnet test`；動到 `extension/` 時另外跑 `cd extension; node --test`。
