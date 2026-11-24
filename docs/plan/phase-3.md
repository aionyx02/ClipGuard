# Phase 3：瀏覽器端（擴充功能、userscript、試玩網頁、文件網站）

> 分支：`feature/phase-3-browser` → PR 到 `dev`（在 Phase 2 的 PR 合併之後）
> 依賴：`@paste-warden/core`（Phase 2 §2.6 的 API 與 §2.2 Report）。在 core-js 完成前，先用同一份 TypeScript 介面的假實作開發。
> 參考：`docs/spikes/s2-wasm-csp.md`（架構與 CSP 結論）、`s9-native-messaging.md`、`docs/THREAT_MODEL.md` T1–T3、T6、T17、T18

## 3.1 範圍

| 元件 | 位置 | 技術 |
|---|---|---|
| 共用 UI | `packages/ui` | React + TypeScript + Tailwind；VerdictCard、OnionTrace（洋蔥視圖）、MaskPreview、SecretList、ThemeProvider、LocaleProvider |
| 注入網頁的警告層 | `packages/overlay` | Preact（或原生 DOM）+ Shadow DOM，越小越好 |
| 擴充功能 | `apps/extension` | WXT，輸出 Chrome / Edge（MV3）與 Firefox |
| Userscript | `apps/userscript` | vite-plugin-monkey，單一 `paste-warden.user.js` |
| 試玩網頁 | `apps/web` | Vite + React；部署到 GitHub Pages |
| 文件網站 | `apps/docs` | Starlight（Astro），繁中 + English；和 `apps/web` 一起部署 |

## 3.2 擴充功能架構（依 S2）

```
MAIN world（hook）──同步 CustomEvent──▶ isolated content script（WASM 引擎）
   │ 包住 navigator.clipboard.writeText / write、            │ 判定 → 回傳給 MAIN world
   │ execCommand('copy')、copy 事件的 clipboardData.setData   │ 顯示 Shadow DOM 警告層
   ▼                                                         ▼
 網頁寫入剪貼簿的當下就攔：quarantine → 擋下寫入或換成     background（設定、規則版本、
 無害提示文字；warn → 放行但顯示警告                         必要時用 offscreen 覆寫剪貼簿）
```

- **寫入剪貼簿時攔截（ClickFix 源頭）**：判定為 `quarantine` 時，寫入內容換成無害文字（例如「PasteWarden 已攔截這個網站放進剪貼簿的指令」），並在頁面顯示警告層：來源網址、白話說明、洋蔥視圖（展開）、「我確定安全，放行一次」。
- **貼上機密時攔截**：沿用舊版插件行為（`docs/spec/detection-rules.md` §7）：偵測到機密才攔下 paste 事件；選項是貼遮罩版（預設，Enter）、貼原文、取消（Esc）；密碼欄位不處理。
- **Pastejacking**：比對使用者選取的文字和網頁寫入的內容（`pastejack` 規則）。
- **通訊安全**（T17）：CustomEvent 名稱每頁隨機產生，MAIN world 只送「要判定的文字」，回傳只有判定和已翻譯的說明，不含設定或其他頁面的資訊。
- **所有 frame**：`all_frames` + `match_origin_as_fallback`（T18）。
- **權限最小化**：不要 `<all_urls>` 以外的 host 權限；不要 `tabs`、`history`；`storage` 用於設定；`offscreen`（Chrome）只在需要覆寫剪貼簿時使用。
- **只裝擴充功能也要完整運作**；Native Messaging（Phase 4）是加分項，不是必要。

## 3.3 設定頁與彈出視窗

- **彈出視窗**：目前頁面的狀態、最近攔截的紀錄（只存網域、時間、種類、遮罩字串，不存原文）、開關。
- **設定頁**：
  - 嚴格度（預設嚴格）：逐項開關，同 `Settings`（Phase 1 §1.1）。
  - 個資包：依 `navigator.languages` 預設，可手動調整。
  - 語言：系統 / 繁中 / English；外觀：系統 / 淺色 / 深色。
  - 允許清單：哪些網站不攔截（例如自己公司的內部工具）。
- **深淺色**：Tailwind `dark:` + `prefers-color-scheme`；注入網頁的警告層跟隨 OS，不跟隨網頁。
- **語言**：UI 字串放在 `locales/{zh-TW,en}/ui*.ftl`，依元件分檔、各用自己的前綴：`ui.ftl`（`ui-`，擴充功能與共用）、`ui-components.ftl`（`ui-comp-`，`@paste-warden/ui`）、`ui-overlay.ftl`（`ui-overlay-`）、`ui-web.ftl`（`ui-web-`，試玩網頁）。`@paste-warden/ui` 的 Fluent loader 在**建置時**用 Vite `import.meta.glob` 把全部 `ui*.ftl` 內嵌進 bundle，所以 UI 不必等引擎載入就有字串（試玩網頁的骨架畫面、警告層都靠這個）。`@paste-warden/core` 的 `messages(locale)` 回傳引擎建置時內嵌的所有 `ui-*` 字串，可透過 `LocaleProvider` 的 `messages` 覆寫建置時的版本（例如字串跟著規則版本更新的情境）；試玩網頁和引擎一起建置，不需要覆寫。引擎訊息（判定原因、步驟說明、機密標籤）已經在 Report 裡翻譯好。
  - *與原規格的差異*：原本寫「由 `messages()` 提供」。實作改成建置時內嵌、`messages()` 只做覆寫，因為 UI 在 `await init()` 之前就要能顯示（骨架、錯誤訊息），而且同一份 `.ftl` 也由 Rust 的 `paste-warden-i18n` 內嵌並檢查兩種語言的 id 一致。

## 3.4 Userscript

- 功能同擴充功能的 content script 部分：寫入剪貼簿攔截、貼上機密攔截、pastejacking。
- 依 S2：`@inject-into content`（Violentmonkey / Tampermonkey），`@grant GM_setValue / GM_getValue` 存設定。
- `WebAssembly` 不可用時（iOS Userscripts、嚴格 CSP 且只能注入 page）改用 wasm2js 版本。
- 單檔大小盡量 < 2 MB；`@updateURL` / `@downloadURL` 指向 GitHub Releases。

## 3.5 試玩網頁（`apps/web`）

- **試玩**：貼上任何文字 → 即時顯示判定、風險分數、白話說明、**洋蔥視圖**（每一層解混淆的動畫展開）、偵測到的機密與遮罩預覽。全部在瀏覽器端用 WASM 執行，不送出任何資料（頁面上明說）。
- **範例按鈕**：無害的 ClickFix 樣本（`calc`、`example.invalid`）、混淆範例、個資範例（假資料）。
- **下載頁**：各平台下載連結與安裝說明的入口（連到文件網站）。
- 深淺色、繁中 / English 切換，網址記住語言（`?lang=en`）。
- 部署：GitHub Actions → GitHub Pages（`/` 是網頁，`/docs/` 是文件網站）。自訂網域之後再設定。
- 實作備註（`apps/web`）：
  - 引擎在第一次渲染後才 lazy-load（`import('@paste-warden/core')` + `init()`），之前顯示同尺寸的骨架（不造成版面位移）；`init()` 在 WebAssembly 不可用或被擋時自動改用 wasm2js（`?engine=wasm2js` 可強制，用於測試）。
  - 「全部在瀏覽器執行、不上傳」由瀏覽器強制：建置版加上 CSP meta（`default-src 'none'; connect-src 'self'; script-src 'self' 'wasm-unsafe-eval'`），沒有分析追蹤、外部字型或 cookie；文字不存 storage、不放網址；textarea 關掉拼字檢查（加強版拼字檢查會把文字送到伺服器）。Playwright 測試斷言載入只有同源請求、分析期間零請求、離線可用、CSP 會擋外部連線。
  - 範例全部在執行時產生：ClickFix 片段組合（`calc`、`example.invalid`）、四層混淆（`^` 跳脫 → `-EncodedCommand` → 字串拼接 → unwrap）、依檢查碼算出的身分證字號與 Luhn 卡號、種子固定的假 GitHub token、從公開字串算出的 BIP-39 助記詞（檢查碼正確 vs 只換最後一個字而檢查碼錯誤）。
  - 連到文件網站一律用相對路徑（`./docs/…`），所以部署在 `/` 或 `/<repo>/` 都能用。

## 3.6 文件網站（`apps/docs`）

- Starlight，繁中為主、English 次之；側欄分「使用者」和「開發者」。
- 第一批頁面：介紹、各平台安裝（Chrome / Edge 載入未封裝、Firefox xpi、userscript、桌面版待 Phase 4）、功能說明、隱私承諾、威脅模型（引用 `docs/THREAT_MODEL.md`）、偵測規格（引用 `docs/spec/`）、agent hook 與 MCP（引用 Phase 2 文件）。
- macOS 安裝說明**不能**教使用者貼 `xattr` 指令（roadmap §8）。

## 3.7 測試

- 單元：Vitest（`packages/*`、`apps/*`）。
- 端對端：Playwright（Chromium + Firefox）載入擴充功能，對本機測試頁（無 CSP、`script-src 'self'`、嚴格 nonce CSP）驗證：
  1. 網頁 `writeText` 一段 ClickFix 樣本 → 剪貼簿內容被換掉、頁面出現警告層。
  2. `execCommand('copy')` 與 `copy` 事件改寫 → 同上。
  3. 在 textarea 貼上假身分證 → 出現確認框；Enter 貼遮罩版；Esc 取消。
  4. 一般文字 → 完全不介入。
  5. iframe 內的寫入也被攔截。
- **不能動到開發者自己的瀏覽器設定檔**：一律用 Playwright 的瀏覽器與暫存 user-data-dir（S2、S9 的做法）。測試結束還原任何系統剪貼簿變更。

## 3.8 完成條件

- [ ] `pnpm -r build` 產出：Chrome zip、Firefox xpi（未簽章，簽章在 Phase 6）、userscript、網頁與文件網站的靜態檔。
- [ ] §3.7 的端對端測試在 CI（Linux headless）通過。
- [ ] 試玩網頁部署到 GitHub Pages（需要先在 repo 設定啟用 Pages）。
- [ ] 文件網站第一批頁面上線，繁中與 English 都有。
- [ ] 深淺色、語言切換在擴充功能、網頁、文件網站都能用。
- [ ] CI：`js` job 跑 Biome、Vitest、Playwright。
