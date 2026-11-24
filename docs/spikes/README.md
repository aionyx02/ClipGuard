# Spike 報告

Phase 0 要在動工前驗證的技術風險。剩下的 spike 怎麼做見 [`HOWTO.md`](HOWTO.md)。每個 spike 完成後，在這個資料夾新增 `sN-<主題>.md`，並更新下表的狀態。

**報告格式**：結論（可行 / 不可行 / 有條件可行）→ 數據 → 遇到的坑 → 建議做法 → 待決問題。Spike 的程式不合併，可以放在個人分支或暫存資料夾。

| # | 題目 | 平台 | 負責 | 狀態 | 報告 |
|---|---|---|---|---|---|
| S1 | WASM 大小與速度 | 任意（需要 rustup 的 wasm32 target） | A | ✅ 可行（gzip 250 KiB） | [`s1-wasm-size.md`](s1-wasm-size.md) |
| S2 | CSP 環境下的 WASM（擴充功能、userscript） | Chrome、Firefox | C | ✅ 可行 | [`s2-wasm-csp.md`](s2-wasm-csp.md) |
| S3 | Windows 剪貼簿監聽、鍵盤 hook、前景視窗 | **Windows 實機** | B | 待執行 | |
| S4 | macOS 監聽與 CGEventTap 授權 | macOS | B | ✅ 可行 | [`s4-macos-monitor.md`](s4-macos-monitor.md) |
| S5 | Linux X11 / Wayland | **Linux 實機**（GNOME + KDE 或 Sway） | B | ⚠️ 有條件可行（GNOME / KDE 待 VM 實測） | [`s5-linux-monitor.md`](s5-linux-monitor.md) |
| S6 | Tauri v2 Android：`PROCESS_TEXT`、分享 intent | **Android 手機或模擬器** | B | ✅ 有條件可行 | [`s6-android.md`](s6-android.md) |
| S7 | Agent 介接：Claude Code / opencode hook、rmcp MCP server | macOS | D | ✅ 可行 | [`s7-agent-integration.md`](s7-agent-integration.md) |
| S8 | 不執行的語法驗證：`pwsh` AST、`bash -n`、cmd 替代方案 | 任意（需要 `pwsh`） | D | ✅ 有條件可行 | [`s8-syntax-validation.md`](s8-syntax-validation.md) |
| S9 | Native Messaging：host manifest 安裝、互相發現、身分驗證 | Windows + macOS，Chrome + Firefox | B、C | macOS ✅ 可行；Windows 待執行 | [`s9-native-messaging.md`](s9-native-messaging.md) |

## 各 spike 要回答的問題

### S1 WASM 大小與速度
- 用 `regex` 把 `rules/*.json` 全部編譯好，加上一個假的 `analyze`，編成 `wasm32-unknown-unknown`（`profile.release-wasm`、`wasm-opt -Oz`）後有多大？目標 gzip < 1.5 MB。
- 在瀏覽器裡：初始化（編譯 RegexSet）要多久？分析 1 KB、1 Mi 字各要多久？和原生版差幾倍？
- 有沒有辦法把規則在 build time 預先編譯（例如 `regex-automata` 的序列化 DFA），換取更快的初始化？代價是多少大小？

### S2 CSP 環境下的 WASM
- 在設定 `script-src 'self'`（沒有 `wasm-unsafe-eval`）的網站上，以下位置能不能 `WebAssembly.instantiate`：content script（isolated world）、MAIN world、background service worker / event page、offscreen document？Chrome 和 Firefox 分別測。
- Tampermonkey、Violentmonkey、iOS Userscripts 裡的 userscript 能不能用 WASM？
- 不能用的地方：wasm2js 輸出的大小和速度如何？訊息傳遞到 background 的延遲多少？
- 寫入剪貼簿當下（`navigator.clipboard.writeText`、`execCommand('copy')`、`copy` 事件）攔截，從 MAIN world 送到分析引擎再回來的總延遲。

### S3 Windows
- Tauri 裡用 `windows` crate 建 message-only window + `AddClipboardFormatListener`；讀 `CF_UNICODETEXT`；辨識 `ExcludeClipboardContentFromMonitorProcessing`、`CanIncludeInClipboardHistory`。
- `SetWindowsHookEx(WH_KEYBOARD_LL)` 攔 Ctrl+V，回呼延遲多少；`EVENT_SYSTEM_FOREGROUND` 取得前景視窗的 class、標題、行程名稱。
- Windows Defender、SmartScreen 對未簽章的執行檔反應如何？要不要送 Microsoft 申訴？

### S4 macOS
- `objc2-app-kit` 輪詢 `NSPasteboard.changeCount`（250 ms）＋ `autoreleasepool`，長時間執行的記憶體與 CPU。
- 偵測 `org.nspasteboard.ConcealedType` 等標記。
- CGEventTap 攔 Cmd+V 需要的權限（輔助使用、輸入監控），引導使用者授權的流程，未授權時如何降級。

### S5 Linux
- X11：XFixes selection 事件；Wayland：`wlr-data-control` / `ext-data-control`。GNOME、KDE、Sway 各能做到什麼？
- 不支援時怎麼偵測並告知使用者。

### S6 Android
- Tauri v2 Android 能不能宣告 `ACTION_PROCESS_TEXT`（選取文字 → 選單出現「PasteWarden 檢查」）與 `ACTION_SEND` 分享目標，並把文字交給 Rust 核心。
- 回傳遮罩後的文字（`EXTRA_PROCESS_TEXT`）取代原選取，在哪些 App 有效。

### S7 Agent 介接
見 `s7-agent-integration.md`。

### S8 語法驗證
- `pwsh` 的 `[System.Management.Automation.Language.Parser]::ParseInput()` 在 macOS / Linux 是否可用、每次呼叫的成本（要不要常駐一個 pwsh 行程）。
- `bash -n`、`zsh -n` 對多行 payload 的行為；有沒有任何路徑會真的執行（例如 `$(...)` 在 `-n` 下不會執行，需驗證）。
- cmd.exe 沒有不執行的語法檢查：自寫 tokenizer 的可行範圍。

### S9 Native Messaging
- Chrome、Firefox 的 host manifest 位置（Windows registry、macOS / Linux 檔案路徑），由 Tauri 安裝程式寫入與移除。
- 雙方如何確認對方身分：`allowed_origins` 限定 extension ID；桌面端如何驗證呼叫者。
- 只裝其中一個時的行為：擴充功能偵測不到 host 要安靜降級。
