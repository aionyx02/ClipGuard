# 剩下的 spike 怎麼做

S3、S5、S6、S9 需要特定平台。每個 spike 都可以交給 Claude Code 執行，人只負責準備環境，以及需要實際按鍵、授權的步驟。

## 通用步驟

1. 準備環境（見各節），安裝 Rust（官方 rustup）與 Claude Code。
2. 取得程式碼：
   ```sh
   git clone https://github.com/aionyx02/paste-warden.git
   cd paste-warden
   git switch feature/phase-0-foundation
   ```
3. 在 repo 目錄啟動 Claude Code，貼上該 spike 的 prompt（見各節）。
4. 完成後確認 `docs/spikes/sN-*.md` 已經寫好，並更新 `docs/spikes/README.md` 的狀態欄，然後 commit 並 push 到 `feature/phase-0-foundation`。

**所有 spike 的共同規則**：spike 程式放在 repo 外的暫存資料夾；只把報告寫進 repo；不要印出或記錄剪貼簿內容（只印長度、類型、變動次數）；需要寫入系統剪貼簿時，先備份、測完立刻還原。

## S3 Windows（建議：組員的 Windows 實體電腦）

發表現場用的就是 Windows，而 Defender、SmartScreen 的反應在實體 x64 電腦上最準，所以優先用實體電腦。沒有的話，可以在 Mac 上用 VMware Fusion 裝 Windows 11 ARM（API 行為相同，但 Defender 的判斷不一定一樣）。

**環境**：
- [rustup-init.exe](https://rustup.rs)
- Visual Studio Build Tools，勾選「使用 C++ 的桌面開發」
- Git
- Node.js 22 以上
- Claude Code

**Prompt**：
> 執行 spike S3。先讀 `CLAUDE.md`、`docs/spikes/README.md` 的 S3 題目，以及 `docs/spikes/s4-macos-monitor.md`（macOS 版的做法與發現，當作參考格式）。在 repo 外的暫存資料夾建立拋棄式 Rust 專案，用 `windows` crate 實作：message-only window + `AddClipboardFormatListener`、讀 `CF_UNICODETEXT`、偵測 `ExcludeClipboardContentFromMonitorProcessing` 和 `CanIncludeInClipboardHistory`、`SetWindowsHookEx(WH_KEYBOARD_LL)` 攔截並吞掉 Ctrl+V、`SetWinEventHook(EVENT_SYSTEM_FOREGROUND)` 取得前景視窗的 class、標題、行程名稱；`EmptyClipboard` 後只寫純文字，確認 `CF_HTML` 和 RTF 都清掉了。量測 CPU 和記憶體、hook 延遲。最後把未簽章的 release exe 下載到另一個資料夾執行（模擬使用者下載），記錄 SmartScreen 和 Defender 的反應。需要我操作（複製、按 Ctrl+V、在密碼管理器複製）時，告訴我要執行的指令和要做的事。報告寫到 `docs/spikes/s3-windows-monitor.md`（繁體中文）。

**人要做的事**：依照提示複製文字、按 Ctrl+V、從密碼管理器（1Password、Bitwarden 等）複製密碼。

## S5 Linux（可以在這台 Mac 上做）

- **X11、wlroots 系列 Wayland**：用 OrbStack 開 Ubuntu 機器或 Docker 容器，在裡面跑 Xvfb 和 headless sway（`WLR_BACKENDS=headless`），不需要螢幕。
- **GNOME、KDE 的 Wayland**：要完整桌面，用 VMware Fusion 裝 Ubuntu Desktop（GNOME）和 Kubuntu（KDE），各測一次。

**Prompt**：
> 執行 spike S5。先讀 `CLAUDE.md`、`docs/spikes/README.md` 的 S5 題目和 `docs/spikes/s4-macos-monitor.md`。用 OrbStack 建 Ubuntu 環境：(1) Xvfb 加 XFixes selection 事件，監聽 CLIPBOARD 變動；(2) headless sway 加 `wlr-data-control` 或 `ext-data-control` 監聽；兩者都用 Rust 寫拋棄式程式，並用 `xclip` / `wl-copy` 產生剪貼簿變動。列出 GNOME、KDE 是否支援這些協定（查文件），以及偵測「不支援」的方法。如果需要完整桌面驗證，告訴我要在 VMware Fusion 裝什麼、做哪些步驟。報告寫到 `docs/spikes/s5-linux-monitor.md`。

## S6 Android（可以在這台 Mac 上做）

用 Android Studio 的模擬器（Apple Silicon 用 arm64 映像）。

**環境**：在 Android Studio 的 SDK Manager 安裝 SDK Platform（API 35 以上）、NDK、Command-line Tools，再建立一台 Pixel 模擬器。Rust 要加 target：`rustup target add aarch64-linux-android`。另外需要 Node.js 和 pnpm（Tauri CLI）。

**Prompt**：
> 執行 spike S6。先讀 `CLAUDE.md` 和 `docs/spikes/README.md` 的 S6 題目。在 repo 外的暫存資料夾用 Tauri v2 建立最小的 Android App：宣告 `ACTION_PROCESS_TEXT`（選取文字後的選單出現「PasteWarden 檢查」）和 `ACTION_SEND`（分享目標）；收到的文字交給 Rust 函式（假的偵測：含 `PW_SPIKE` 就判定有機密）；回傳遮罩後的文字（`EXTRA_PROCESS_TEXT`），確認能取代原本選取的文字。在模擬器上用 Chrome、Google Keep、Messages 各測一次。另外確認 Android 10 以上背景讀剪貼簿確實被擋（寫一段測試記錄結果）。需要我在模擬器上點選時，告訴我步驟。報告寫到 `docs/spikes/s6-android.md`。

## S9 Native Messaging（Mac 部分在這台做，Windows 部分和 S3 一起做）

**Prompt（macOS）**：
> 執行 spike S9 的 macOS 部分。先讀 `CLAUDE.md`、`docs/spikes/README.md` 的 S9 題目、`docs/spikes/s2-wasm-csp.md`、`docs/THREAT_MODEL.md` 的 T16。在 repo 外的暫存資料夾寫一個 Rust native messaging host（stdin/stdout、4-byte 長度前綴的 JSON），以及最小的 Chrome MV3 和 Firefox 擴充功能。把 host manifest 裝到 Chrome 和 Firefox 在 macOS 的使用者層級路徑（`allowed_origins` / `allowed_extensions` 只放測試用的 extension ID）。驗證：雙向傳訊息；host 不存在時擴充功能如何安靜降級；用另一個 extension ID 連線會被拒絕；host 端如何確認呼叫者（Chrome 會把 origin 當成第一個參數傳入）。量測延遲。測完移除 host manifest。報告寫到 `docs/spikes/s9-native-messaging.md`，Windows 部分（registry 位置）標成待補。

**Windows 部分**：在 S3 的電腦上，請 Claude Code 讀 `s9-native-messaging.md`，補上 Windows 的 registry 位置（`HKCU\Software\Google\Chrome\NativeMessagingHosts\…`、Firefox 的對應位置）和實測結果。
