# S5 Linux：X11 / Wayland 剪貼簿監聽、密碼管理器標記、前景視窗、攔截 Ctrl+V

- 日期：2026-11-24　平台：OrbStack（Apple Silicon，arm64 Linux 容器）
- 環境：Ubuntu 25.10（Xvfb、openbox、sway 1.10.1、wl-clipboard 2.2.1、KeePassXC 2.7.10 / Qt5）；Alpine edge（sway 1.12 / wlroots 0.20.2、wl-clipboard 2.3.0）
- 版本：Rust 1.100、`x11rb` 0.13（`xfixes`、`res`）、`wayland-client` 0.31、`wayland-protocols` 0.32（`staging`）、`wayland-protocols-wlr` 0.3
- Spike 程式放在暫存資料夾，不合併：`x11mon`（XFixes 監聽）、`grab`（XGrabKey 實驗）、`wlmon`（`monitor` / `write`，ext 或 wlr data-control）。**程式只印變動次數、targets / MIME 類型和長度，不印任何剪貼簿內容**；寫入測試只寫 `*` 佔位字元。
- GNOME、KDE 的完整桌面沒有實測，見「待決問題」。

## 結論：有條件可行

| 項目 | 結果 |
|---|---|
| X11：XFixes `SelectionNotify`（CLIPBOARD） | ✅ `xclip` 連續 300 次變動，事件 302 筆全收到；變動到讀完長度 0.2–0.6 ms |
| Wayland：`zwlr_data_control_manager_v1`（sway 1.10） | ✅ 監聽 + 讀長度都可以 |
| Wayland：`ext_data_control_manager_v1`（sway 1.12） | ✅ 監聽 + 讀長度都可以；同一個 compositor 兩種協定並存 |
| Wayland 寫入（遮罩 / 隔離要用） | ✅ `create_data_source` + `set_selection`，`wl-paste` 讀到我們的內容；被別人取代時收到 `cancelled` |
| 密碼管理器標記 `x-kde-passwordManagerHint` | ✅ **真的 KeePassXC** 在 X11 和 Wayland 都會帶，monitor 看到就跳過，完全沒讀文字 |
| 前景視窗 | X11 ✅（`_NET_ACTIVE_WINDOW`、`WM_CLASS`、pid）；Wayland ⚠️ 只有 compositor 專屬做法 |
| 攔截 Ctrl+V | X11 ✅ `XGrabKey` 能吞掉；Wayland ❌ 沒有標準做法 |
| 閒置成本 | 兩個 monitor 都是事件驅動、無輪詢：閒置 120 秒 CPU 0 ticks，RSS 約 1–2 MB（X11 峰值 2.4 MB）；300 次變動共 1–3 ticks（10–30 ms） |
| GNOME（Mutter） | ❌ 不支援任何 data-control 協定，要另外處理（見建議做法） |

## 數據

### 各 compositor 支援的 data-control 協定（2026 年底）

| Compositor | `ext-data-control-v1` | `zwlr-data-control-v1` | 來源 / 備註 |
|---|---|---|---|
| GNOME / Mutter 51 | ❌ | ❌ | 長期 issue [mutter#524](https://gitlab.gnome.org/GNOME/mutter/-/issues/524) 未實作 |
| KDE / KWin 6.7 | ✅ | ❌（**6.5 移除**） | 只寫 wlr 的工具在 6.5 壞掉：[KDE bug 513822](https://bugs.kde.org/show_bug.cgi?id=513822)、[511511](https://bugs.kde.org/show_bug.cgi?id=511511) |
| sway | ✅ 1.11 起（實測 1.12） | ✅（實測 1.10、1.12） | |
| Hyprland 0.57 | ✅ | ✅ | |
| COSMIC 1.x | ✅ | ✅ | 要設 `COSMIC_DATA_CONTROL_ENABLED=1` 才開放（[cosmic-comp#600](https://github.com/pop-os/cosmic-comp/issues/600)） |
| labwc、niri、river、Wayfire | labwc/niri/river ✅、Wayfire ❌ | ✅ | |

總表來源：[wayland.app ext-data-control-v1](https://wayland.app/protocols/ext-data-control-v1)、[wlr-data-control](https://wayland.app/protocols/wlr-data-control-unstable-v1)（wlr 版已標為 deprecated）。協定在 wayland-protocols 1.39 進入 staging。

### KeePassXC 設的標記（原始碼 + 實測）

`src/gui/Clipboard.cpp`（develop 分支）在 `Q_OS_UNIX` 用 `setData("x-kde-passwordManagerHint", "secret")`，**而且同時寫進 PRIMARY selection**。實測：
- X11：CLIPBOARD 的 TARGETS 是 `text/plain, UTF8_STRING, STRING, TEXT, x-kde-passwordManagerHint, TARGETS, MULTIPLE, TIMESTAMP, SAVE_TARGETS`；PRIMARY 一樣，長度 24（產生的密碼）。
- Wayland（Qt5 wayland plugin，sway）：MIME 是 `text/plain, x-kde-passwordManagerHint, text/plain;charset=utf-8`。
- 這是 Klipper 2018 年起的慣例，CopyQ、KWalletManager 24.08+ 也遵守。Linux 上沒有其他通用標記（沒有 Windows `ExcludeClipboardContentFromMonitorProcessing` 或 macOS `ConcealedType` 的對應物）。

### 前景視窗

- **X11**：root 的 `_NET_ACTIVE_WINDOW` → `WM_CLASS`（KeePassXC 是 `keepassxc/KeePassXC`）；pid 用 **XRes `QueryClientIds`**，不依賴 `_NET_WM_PID`（`xev` 就沒有設）。需要 EWMH 視窗管理員；沒有 WM 時拿不到。
- **還能拿到「來源 App」**：XFixes 事件帶 selection owner 視窗，用 XRes 查 owner 的 pid → `/proc/<pid>/comm`。KeePassXC 實測拿到 `keepassxc`。坑：XRes 回的是**連線當下**的 pid，`xclip` 連線後 fork 到背景、父行程結束，所以 pid 已失效（comm 讀不到）。
- **Wayland**：協定本身不提供。sway 實測有 `zwlr_foreign_toplevel_manager_v1`（帶 `activated` 狀態，Hyprland、labwc 也有）和 `ext_foreign_toplevel_list_v1`（沒有 activated 狀態，不夠用）；sway IPC `get_tree` 拿到 `app_id=org.keepassxc.KeePassXC` 和 pid。KWin 拒絕實作 wlr 版（[KDE bug 502647](https://bugs.kde.org/show_bug.cgi?id=502647)），要用 KWin scripting 或 KDE 私有的 `plasma-window-management`；GNOME 只能靠 Shell extension。Portal 沒有「目前前景視窗」的 API。

### 攔截 Ctrl+V

- **X11**：`XGrabKey(root, Ctrl+v)`（加上 Lock / NumLock 組合）後，`xdotool key ctrl+v`（XTest）送出，`xev` 視窗收到的 `v` 從 2 次變成 0 次，grab 程式收到 KeyPress；單按 `v` 不受影響。要放行時得先 ungrab 再用 XTest 重送（或 `XSendEvent`，但很多 App 忽略 synthetic event）。XRecord / XInput2 raw events 只能觀察、不能吞。限制：Ctrl+Shift+V（終端機）、滑鼠中鍵貼 PRIMARY、右鍵選單貼上都抓不到；其他程式已經 grab 同一組合鍵時會 `BadAccess`。
- **Wayland**：compositor 不會把別人的按鍵交給一般 client，沒有協定可以吞鍵。唯一跨 compositor 的路是 evdev `EVIOCGRAB` + uinput 重送（keyd 的做法），要 root 或 `input` 群組，等於鍵盤側錄器，**不建議**。

## 遇到的坑

1. **KWin 6.5 拿掉 wlr 版**：只實作 `zwlr_data_control` 的程式在新版 KDE 直接失效。`wl-clipboard` 到 2.3.0 才改用 ext（實測 `WAYLAND_DEBUG` 看到綁的是 `ext_data_control_manager_v1`），2.2.1 只有 wlr。
2. **sway 1.10 沒有 ext 版**：Ubuntu 25.10 的 sway 只有 wlr，要 1.11 以上才有 ext。兩種都要實作。
3. **XWayland 後備在 wlroots 上無效**：sway 開 XWayland，X11 monitor 掛在 `:0`，`wl-copy` 兩次都**沒有**收到 XFixes 事件（wlroots 只在 X11 視窗有焦點時才把 Wayland selection 同步給 X）。Mutter 的行為不同（CopyQ 在 GNOME 就是靠 XWayland 模式），但沒實測。
4. **data-control 的 `receive` 不經過 compositor**：來源 client 直接寫 pipe。讀取要在 `flush()` 之後、不能在 dispatch callback 裡同步讀（會卡住 event queue 的請求送出）。每個 monitor 都會觸發來源一次 `send`（寫入測試 1 個 `wl-paste` + 2 個 monitor = served 3 次），大型內容要設讀取上限和 timeout，否則惡意來源可以讓我們一直讀。
5. **自己寫入也會被自己的 monitor 收到**（`#5` 就是 writer 寫的 32 bytes），要有自我寫入防迴圈的快取（同 macOS）。
6. **X11 連續變動的競態**：300 次 `xclip` 裡 301 次讀到 TARGETS、298 次讀到長度——轉換還沒回來 owner 就換了。正式版要比對 selection timestamp / owner，過期的回覆丟掉。大於 max request size 的內容走 `INCR`，要實作分段讀（Xvfb 有 BIG-REQUESTS，300 KB 直接回來了）。
7. **PRIMARY 也會帶密碼**：KeePassXC 把密碼同時放進 PRIMARY，中鍵就能貼出。出去方向的防護要一起監聽 PRIMARY（`zwp_primary_selection` / data-control 的 `primary_selection` 事件），但 PRIMARY 每次選取文字都會變，只看長度和標記、不要每次都送進引擎。
8. 容器裡的 sway 有 file capability（`cap_sys_nice`），直接執行會 `Operation not permitted`，複製一份去掉 cap 就能跑；KeePassXC 2.7 是 Qt5，要裝 `qtwayland5`；`wtype` 每次呼叫都是新的虛擬鍵盤，修飾鍵要在同一個 `wtype` 指令裡送。

## 建議做法（Phase 4）

- `crates/platform/src/linux/`：
  - `ClipboardMonitor` 依序選後端：
    1. `WAYLAND_DISPLAY` 存在 → 讀 registry，**先綁 `ext_data_control_manager_v1`，沒有再綁 `zwlr_data_control_manager_v1`**。
    2. 兩者都沒有（GNOME）→ 如果有 `DISPLAY`，試 XWayland + XFixes。「XWayland 收不收得到原生 Wayland App 的變動」沒辦法在啟動時自測（自己設的 X selection 一定收得到），所以標記為「未確認」，並在 UI 顯示「這個桌面環境的自動監聽受限」。
    3. 純 X11 → XFixes。
  - 每次變動先看 MIME / TARGETS：有 `x-kde-passwordManagerHint` 就跳過、不讀文字；再讀 `text/plain;charset=utf-8`（X11 是 `UTF8_STRING`，含 INCR），設長度上限與 timeout，原文用 `zeroize`。
  - `ClipboardWriter`：data-control source（Wayland）或成為 X selection owner（X11）；只 offer 純文字；寫入雜湊進防迴圈快取；被 `cancelled` 就結束。
  - `ActiveWindowProvider`：X11 用 `_NET_ACTIVE_WINDOW` 的 PropertyNotify 持續追蹤 + XRes pid；Wayland 有 `zwlr_foreign_toplevel_manager_v1` 就用，否則回報「未知」，Context 不加權。
  - `PasteInterceptor`：只在 X11 提供（XGrabKey）；Wayland 一律降級成「只通知、不攔截」，**在設定頁說清楚原因**。
- **不支援時的處理**：偵測結果寫成 `MonitorCapability { watch, read, write, foreground, intercept }`，UI 依此顯示。GNOME 上提供三條路，讓使用者選：(a) 手動檢查（tray 按鈕，App 取得焦點後用一般 `wl_data_device` 讀，Wayland 允許有焦點的 client 讀）；(b) 安裝 PasteWarden 的 GNOME Shell extension（CopyQ 14 的做法），由 extension 用 D-Bus 通知主程式；(c) 瀏覽器擴充功能（不受桌面環境限制）。
- COSMIC：偵測到 `XDG_CURRENT_DESKTOP=COSMIC` 但沒有 data-control global 時，提示使用者設 `COSMIC_DATA_CONTROL_ENABLED=1`。
- Flatpak 要開 `--socket=wayland` / `--socket=x11`；data-control 在 Flatpak 裡能不能用要另外確認。

## 待決問題

1. **GNOME 實測**（VMware Fusion，Ubuntu 26.04 Desktop arm64，Wayland session）：
   - `wayland-info | grep data_control` 確認沒有任何 data-control global（預期）。
   - 把 `x11mon` 用 `DISPLAY=:0` 跑在 XWayland，從原生 Wayland App（GNOME Text Editor）複製：XFixes 事件有沒有來？App 沒焦點時能不能讀到長度？（CopyQ 說可以，但我們在 wlroots 上實測不行。）
   - 試 GNOME Shell extension 路線：`Meta.Selection` 的 `owner-changed` 訊號能不能拿到 MIME 與內容，以及 extension 的發布流程。
2. **KDE 實測**（Kubuntu 26.04 / Plasma 6.5 以上）：`wlmon monitor` 應綁到 ext；確認 [KDE bug 511173](https://bugs.kde.org/show_bug.cgi?id=511173)（data-control client 造成焦點跳掉）是否影響我們；從 KeePassXC 複製，確認看得到 `x-kde-passwordManagerHint`；KWin scripting 取得前景視窗的成本。
3. Hyprland、COSMIC 只查文件，沒實測。
4. Bitwarden、1Password Linux 版有沒有帶 `x-kde-passwordManagerHint`（Bitwarden 論壇仍在要求這個功能），沒有的話要靠內容偵測。
5. X11 攔截要不要做：XGrabKey 會跟使用者其他快捷鍵工具衝突，而且 X11 使用者越來越少（GNOME 50 已拿掉 X11 session）。建議 Phase 4 先只做 Wayland 的「通知」模式，X11 攔截列為可選。
