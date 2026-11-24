# PasteWarden 威脅模型

> 版本：Phase 0 初版（2026-11）。每個 Phase 結束時檢查一次；新增功能或已知缺口時同步更新。

## 1. 保護什麼

| 資產 | 說明 |
|---|---|
| 使用者的電腦 | 不被誘騙執行惡意指令（ClickFix / FileFix） |
| 使用者的機密 | 個資、卡號、API key、私鑰、助記詞、使用者登記的機密，不被誤貼到網頁或聊天軟體 |
| 使用者的資產 | 加密貨幣轉帳地址不被掉包 |
| AI agent 的執行環境 | agent 不被網頁內容（prompt injection）騙去執行指令或外洩機密 |
| PasteWarden 本身 | 規則、程式更新、設定不被竄改；不成為新的外洩管道 |

## 2. 信任邊界

```
 [網頁 / 文件 / 聊天訊息]  ← 不可信：攻擊者可以完全控制內容
          │ 複製、網頁寫入剪貼簿
          ▼
 ┌──────── 系統剪貼簿 ────────┐  ← 第一道邊界：PasteWarden 監看（桌面）或在寫入當下攔截（擴充功能）
 └───────────┬───────────────┘
             │ 貼上
             ▼
 [Win+R / 終端機 / 網頁表單 / 聊天軟體 / AI agent 的 Bash 工具]  ← 第二道邊界：執行入口警告、貼上前確認、agent hook
```

- 剪貼簿內容一律視為**攻擊者可控的輸入**：偵測引擎必須在任何輸入下都不 panic、不卡住（fuzz + 線性時間 regex）。
- 雲端 LLM 是**不可信的第三方**：機密不能送過去；它的回答也不能降低判定等級。
- 規則包與程式更新來自網路，必須驗證簽章。

## 3. 防禦的威脅（STRIDE 對照）

| # | 威脅 | 類型 | 對策 | Phase |
|---|---|---|---|---|
| T1 | 假驗證頁叫使用者貼上並執行指令（ClickFix / FileFix） | Elevation | 多層解混淆 + 訊號判定；高風險時清空剪貼簿；擴充功能在網頁寫入當下就擋；執行入口再警告 | 1、3、4 |
| T2 | 網頁偷換使用者複製的內容（Pastejacking） | Tampering | 比對選取文字和寫入內容 | 3 |
| T3 | 用看不見的字元藏指令或 prompt（零寬、TAG、BiDi、同形字） | Spoofing | 正規化 + 隱藏字元偵測 | 1 |
| T4 | 混淆繞過偵測（`^`、反引號、字串拼接、編碼） | Evasion | 解混淆最多 5 層；紅隊 agent 持續找繞過，藍隊修補 | 1、5 |
| T5 | 剪貼簿惡意程式把錢包地址換掉（clipper） | Tampering | 時間 + 前後文比對 | 1、4 |
| T6 | 使用者把機密貼到網頁或聊天軟體 | Info disclosure | 偵測 + 遮罩 + 貼上前確認 | 1、3、4 |
| T7 | AI agent 被 prompt injection 騙去執行指令 | Elevation | PreToolUse hook 強制檢查（不靠模型自律） | 2 |
| T8 | AI agent 把機密送出去 | Info disclosure | hook 檢查對外請求的內容 | 2 |
| T7b | hook 程式出錯或逾時時，agent 平台預設放行（fail-open） | Elevation | hook 內部接住所有錯誤和 panic 後回傳 deny；設定很短的內部 timeout；整合測試 | 2 |
| T9 | 被 prompt injection 的 agent 透過 PasteWarden 的 MCP 讀剪貼簿 | Info disclosure | **不提供**讀剪貼簿的工具；輸出一律遮罩；只用 stdio | 2 |
| T10 | 送給 LLM 解說時外洩機密 | Info disclosure | Tier 1 偵測到機密就拒絕呼叫雲端模型；AI 功能預設關閉 | 5 |
| T11 | 攻擊者在指令裡寫 prompt，騙 LLM 說「這很安全」 | Tampering | LLM 只能提高風險等級，不能降低；輸出必須通過 schema 驗證 | 5 |
| T12 | 用超長輸入或病態 regex 輸入讓 PasteWarden 卡死（ReDoS） | DoS | 只用線性時間 regex；所有上限寫成常數；每條規則量測病態輸入 | 1 |
| T13 | 規則包或更新被替換 | Tampering | ed25519 簽章的規則包；Tauri updater 簽章；Artifact Attestations | 3、6 |
| T14 | PasteWarden 自己把剪貼簿內容寫進 log 或檔案 | Info disclosure | P3：不寫檔、不寫 log；`zeroize`；review 檢查清單 | 全部 |
| T15 | 登記的機密被反推 | Info disclosure | 只存 HMAC-SHA256，金鑰放在 OS keyring；禁止單純 SHA-256 | 4 |
| T17 | 網頁偽造或攔截 MAIN world 與 content script 之間的 `CustomEvent` 通道（看到判定、送假請求） | Spoofing / Info disclosure | 通道只傳「要判定的文字」與「判定結果」，不傳機密原文或設定；判定以 isolated world 為準；事件名稱每頁隨機；已配對但沒有回應時 fail closed（擋下寫入） | 3 ✅ |
| T18 | 網頁從 iframe 取得未被 hook 的原生 `clipboard` 函式，繞過寫入攔截 | Evasion | `all_frames` + `match_origin_as_fallback` 注入所有 frame；同源子 frame 在取用 `contentWindow` 或插入時補 hook。**已知缺口**：直接用 `frames[i]`、`innerHTML` 插入後立刻取用；Firefox 未驗證 `match_origin_as_fallback`。桌面版和執行入口警告是第二道防線 | 3 ⚠️ |
| T16 | 擴充功能和桌面程式的互通管道被冒用 | Spoofing | Native Messaging 只接受已知的 extension ID；訊息不含機密原文 | 4 |

## 4. 不在防護範圍內

寫清楚，避免使用者有錯誤的安全感：

| 項目 | 原因 |
|---|---|
| 電腦上已經有惡意程式（可以直接讀剪貼簿、側錄鍵盤） | PasteWarden 不是防毒軟體；錢包掉包偵測只能「發現」，不能阻止 |
| 以系統管理員權限執行的視窗 | Windows UIPI：一般權限的程式看不到也攔不到 |
| 右鍵貼上、拖放、程式自己讀剪貼簿 | 桌面版只攔鍵盤貼上（擴充功能在網頁內可以攔 paste 事件） |
| 使用者看了警告仍然選擇「放行」 | 我們只能提醒和增加摩擦，不能代替使用者決定 |
| 截圖、拍照、OCR 外洩 | 不是剪貼簿 |
| iOS / Android 背景監看 | 作業系統不允許；手機端只提供手動檢查與擴充功能 / userscript |
| Linux Wayland（GNOME） | 沒有可用的剪貼簿監看協定 |
| 偵測規則之外的全新攻擊手法 | 規則式偵測的本質限制；靠紅隊與競技場持續擴充 |

## 5. 設計原則（來自 docs/spec/detection-rules.md）

- **P1 寧可漏擋，不可誤清**：只有確定是詐騙才清空剪貼簿。
- **P3 不留存剪貼簿內容**、**P4 通知不顯示完整機密**。
- **規則是資料**：修補不需要改引擎，可以審核、可以簽章。
- **護欄寫在程式碼裡**：權限、隱私、LLM 的限制都由程式強制，不靠 prompt。
- **預設安全**：嚴格模式、AI 功能關閉、零遙測。

## 6. 待驗證（Phase 0 spike 之後更新）

- Defender 是否把鍵盤 hook 視為惡意（S3）。
- Native Messaging 的身分驗證做法（S9）。
