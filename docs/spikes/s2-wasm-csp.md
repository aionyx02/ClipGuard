# S2 CSP 環境下的 WASM（擴充功能、userscript）

- 日期：2026-11-24　平台：macOS（Darwin 27.2），全部在 headless 瀏覽器裡跑
- 版本：Playwright 1.65.1 內建的 Chromium 159.0.8154.6、Firefox 159.0；Rust 1.100.0、`wasm-bindgen` 0.2.130、`regex` 1.13.2、binaryen `version_132`（npm `binaryen`）、Violentmonkey 2.50.0
- Spike 程式放在暫存資料夾，不合併。假引擎是 Rust 的 `regex`（開了完整 Unicode）計算可疑片段數量，透過 raw C ABI（`pw_alloc`／`pw_count`／`pw_free`）匯出。擴充功能有四個變體：Chrome／Firefox 各一組，每組再分成 extension CSP 有加 `'wasm-unsafe-eval'` 和沒加。
- 測試頁的 CSP：**a** 沒有 CSP；**b** `script-src 'self'`；**c** `default-src 'none'; script-src 'nonce-…' 'strict-dynamic' https: 'unsafe-inline'; connect-src 'self'; require-trusted-types-for 'script'`（仿大型網站）；**d** `script-src 'self' 'wasm-unsafe-eval'`（對照組）。
- Chromium 用 `--load-extension` 載入。Firefox 以 `-start-debugger-server` 啟動 Playwright 的 Firefox，再用 web-ext 的 RDP client 呼叫 `installTemporaryAddon`。兩個瀏覽器都能自動化，表中標 ✅／❌ 的都是**實測**結果。

## 結論：可行，引擎放在 isolated world 的 content script

1. 在 b、c 這類 CSP 底下，**MAIN world 不能跑 WASM**，兩個瀏覽器都會丟 `CompileError`，並觸發 `script-src wasm-eval` violation。**isolated world 的 content script 不受頁面 CSP 限制**，就算 extension CSP 沒寫 `wasm-unsafe-eval` 也能跑。
2. background（Chrome 的 service worker、Firefox 的 event page）和 Chrome 的 offscreen document 一定要在 `content_security_policy.extension_pages` 加上 `'wasm-unsafe-eval'`，否則 `CompileError`。Chrome 和 Firefox 的 MV3 預設 CSP 都沒有這一項。
3. MAIN world 到 isolated world 用 **`CustomEvent` 傳遞是同步的**。所以就算在 `copy` 事件或 `setData` 裡面，也能同步拿到 isolated world WASM 的判定，每次約 15–30 µs（1 KB）。這就是建議架構的關鍵。
4. `window.postMessage` 在 Chromium 的真實點擊 handler 裡，第一個 hop 會延遲一個 frame（約 14 ms），換成 `CustomEvent` 降到 0.1 ms。
5. wasm2js 在所有位置、所有 CSP 下都能跑，因為它就是一般 JS。速度和 WASM 差不多（慢 1.0–1.5 倍），但體積較大，每頁的載入成本也較高。不適合注入每一頁，只適合當備案。

## 能力矩陣（實測）

`WebAssembly.instantiate`，✅ = 成功，❌ = `CompileError`。

| 位置 | Chrome a | Chrome b | Chrome c | FF a | FF b | FF c | extension CSP 要加 `wasm-unsafe-eval` 嗎 |
|---|---|---|---|---|---|---|---|
| 頁面自己的 script（對照組） | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | — |
| MAIN world content script（`world: "MAIN"`） | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | 沒有影響，套用的是頁面 CSP |
| MAIN world 跑 wasm2js | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 不需要 |
| isolated world content script | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | **不需要**（沒加的變體也 ✅） |
| background（SW／event page） | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | **需要**，沒加就 ❌ |
| offscreen document（只有 Chrome） | ✅ | ✅ | ✅ | — | — | — | **需要**，沒加就 ❌ |
| Violentmonkey MV3，`@inject-into page` | ✅ | ❌ | ❌ | 未測 | 未測 | 未測 | — |
| Violentmonkey MV3，`@inject-into content`（USER_SCRIPT world） | ✅ | ✅ | ✅ | 未測 | 未測 | 未測 | — |

其他觀察：
- d 頁（`'wasm-unsafe-eval'`）的 MAIN world 可以跑 WASM，證明擋下 WASM 的確實是 CSP。
- MAIN world 可以 `fetch()` `web_accessible_resources` 裡的 `pw.wasm`，**c 頁設了 `connect-src 'self'` 也能抓**（兩個瀏覽器都是）。但抓到也編譯不了，所以沒有用。
- 自動化載入未封裝的擴充功能要靠 `--load-extension`。Chrome 品牌版已經拿掉這個 flag，Phase 3 的 E2E 測試要用 Playwright 的 Chromium（`channel: 'chromium'`）。

## 延遲（1 KB 字串，200 次）

單位是 ms。Chromium 的 `performance.now()` 精度是 0.1 ms，所以中位數 0 代表不到 0.1 ms。Firefox 測試設定檔關掉了 `privacy.reduceTimerPrecision`。

**A. 從 `page.evaluate` 連續呼叫**（不在輸入事件裡），c 頁，`postMessage` 傳遞：

| 路徑 | Chrome 中位數／p95／平均 | Firefox 中位數／p95／平均 |
|---|---|---|
| MAIN → CS（WASM）→ MAIN | <0.1 / 0.1 / 0.017 | 0.02 / 0.04 / 0.024 |
| MAIN → CS → background（WASM）→ 回來 | 0.2 / 0.3 / 0.17 | 0.18 / 0.26 / 0.20 |
| MAIN → CS → SW → offscreen（WASM）→ 回來 | 0.3 / 0.4 / 0.32 | — |
| MAIN → CS → offscreen（直接 `sendMessage`） | 0.2 / 0.3 / 0.18 | — |

**B. 在真實 click handler 裡量**（Playwright 送出的 trusted 點擊，每種 30 次，c 頁），中位數／p95：

| 路徑 | Chrome `postMessage` | Chrome `CustomEvent` | Firefox `postMessage` | Firefox `CustomEvent` |
|---|---|---|---|---|
| → CS | **14.7 / 15.7** | 0.1 / 0.3 | 0.28 / 0.40 | 0.22 / 0.32 |
| → background | 1.3 / 1.9 | 0.8 / 1.2 | 1.6 / 2.3 | 1.8 / 2.3 |
| → offscreen（經過 SW） | 1.2 / 1.9 | 1.0 / 1.4 | — | — |

Chrome 那 14 ms 是 `postMessage` 的 task 被排到下一個 frame 之後，只有第一個 hop 會遇到。改用 `CustomEvent`，同步 dispatch 到 CS 就沒有這段延遲。

**C. 同步呼叫 `askSync`**（`CustomEvent` → CS 的 WASM → `CustomEvent`，全程不經過 event loop）：Chrome 每次 0.015 ms，Firefox 0.029 ms。

沒測的部分：SW 閒置 30 秒被終止後的冷啟動。推論是第一則訊息要多等 SW 啟動，再加上重新 instantiate（約 3–12 ms）。建議架構的熱路徑完全不經過 SW，所以影響不大。

## 攔截剪貼簿寫入（c 頁，兩個瀏覽器都實測）

用 `Clipboard.prototype.writeText` 包一層：回傳的 promise 等判定出來才 resolve。

| 情境 | Chrome | Firefox |
|---|---|---|
| 判定為惡意，`throw NotAllowedError` | ✅ 頁面收到 reject，剪貼簿沒變 | ✅ |
| 判定為安全，等 0、1、4 秒後才呼叫原本的 `writeText` | ✅ 寫入成功 | ✅ |
| 等 6 秒後才呼叫 | ❌ `Write permission denied` | ❌ `lack of user activation` |
| 對照：最後一次使用者操作 5.5 秒後，呼叫沒被 hook 的 `writeText` | ❌ | ❌ |

所以**可以「卡住」`writeText`**。transient activation 大約 5 秒，判定只要 1 ms 左右，時間很充裕。注意：Chromium 的 `page.evaluate` 會帶 `userGesture`，測「沒有手勢」的情境要另外排 `setTimeout` 讓 activation 過期。

`execCommand('copy')`、`copy` 事件、`clipboardData.setData` 都是同步的。我們 hook `DataTransfer.prototype.setData`，在 copy 事件期間攔下文字：

| 模式 | Chrome | Firefox | 說明 |
|---|---|---|---|
| `sync`：MAIN world 的 wasm2js 同步判定，當場換掉內容 | ✅ | ✅ | Firefox 第一次呼叫因為 JIT 還沒暖機，花了 15.8 ms |
| **`sync-cs`：用 `CustomEvent` 同步問 isolated world 的 WASM** | ✅ 0.2–0.6 ms | ✅ 0.3 ms | 鍵盤 Cmd/Ctrl+C 也一樣 ✅ |
| `hold`：先寫入「檢查中」佔位文字，判定後再用 `writeText` 寫回 | ✅ | ✅ | 如果寫回失敗，剪貼簿會留著佔位文字（實際遇過） |
| `optimistic`：先放行，判定後用 `writeText` 覆寫 | ✅ | ✅ | 中間有大約 1 ms 的空窗 |
| `optimistic`，判定 6 秒後才出來 | MAIN ❌ → offscreen 的 `execCommand('copy')` ✅ | MAIN ❌ → background 的 `navigator.clipboard.writeText` ✅ | offscreen 的 `navigator.clipboard.writeText` 會報 `Document is not focused` |
| 由擴充功能端寫入，完全沒有使用者手勢 | ✅（offscreen + `clipboardWrite`） | ✅（background） | 這是覆寫失敗時的退路 |

**能做到的最好結果**：在 copy 事件裡就同步判定並換掉內容（`sync-cs`），不會有任何空窗。只有在同步路徑不能用時，才退回 `optimistic` 加擴充功能端覆寫。

## wasm2js 備案

| | `.wasm`（`wasm-opt -Oz`） | wasm2js | wasm2js + terser |
|---|---|---|---|
| 大小 | 834,465 B | 4,600,072 B | 1,463,497 B |
| gzip／brotli | 294,634 / 206,408 B | 630,031 B / — | 456,108 / 293,858 B |
| 載入成本（Chrome／Firefox） | instantiate 12 ms / 3 ms | eval 16 ms / 46 ms | 12 ms / 32 ms |
| 1 KB 呼叫一次（Chrome／Firefox） | 3.0–3.6 µs / 3.4 µs | 3.7–4.3 µs / 4.8 µs | — |
| 100 KB 呼叫一次（Chrome／Firefox） | 0.24–0.41 ms / 0.48 ms | 0.35–0.47 ms / 0.49 ms | — |

大小主要來自 `regex` 的 Unicode 表，真正的引擎大小要等 Phase 3 再量。WASM 被擋的地方（b、c 的 MAIN world、沒加 CSP 的 background），wasm2js 都**能跑**。

建置時踩到的坑，`packages/core-js` 要處理：
- `wasm-bindgen` 0.2.130 的輸出會用到 externref table（reference-types），wasm2js 直接失敗：`modules with multiple tables are not supported yet`。
- 用 `-C target-feature=-reference-types` 關掉 reference-types 後，`wasm-bindgen` 也會失敗：`failed to find intrinsics to enable clone_ref`。
- `wasm-opt --all-features` 會產生 tail call，wasm2js 不支援。必須明確列出要開的 feature（bulk-memory、sign-ext、nontrapping-float-to-int、mutable-globals、reference-types、multivalue）。
- 結論：**wasm2js 這條路要走 raw C ABI**，不要經過 `wasm-bindgen` glue。最簡單的做法是 WASM 也直接用同一套 raw ABI 和手寫的 glue，兩邊共用。raw ABI 需要 `unsafe`，要放在 `crates/wasm`，不能放進 `#![forbid(unsafe_code)]` 的 core。

## Userscript

- **實測（Chromium）**：Violentmonkey 2.50.0 MV3，要先在 `chrome://extensions` 打開「允許使用者指令碼」。它用 `chrome.userScripts`，並且 `configureWorld({csp:"script-src 'self' 'unsafe-inline' 'unsafe-eval'…"})`。
  - `@inject-into page`、`@grant none`：跑在頁面 context，b、c 的 WASM 和 `new Function` 都被擋。
  - `@inject-into content`：跑在 USER_SCRIPT world，a 到 d 的 WASM 都 ✅。
- **未測，推論**：
  - Firefox 版 Violentmonkey（MV2）可以用 temporary add-on 載入，但 Playwright 抓不到它的安裝確認頁，所以沒裝成。依照 Firefox isolated content script 的結果，推論 `content` 模式 ✅、`page` 模式在嚴格 CSP 下 ❌。
  - Tampermonkey 是閉源，只能從商店安裝，沒測。它的 MV3 版同樣用 `userScripts` API，推論 `@grant none` 或注入 page 的腳本會被 CSP 擋；跑在 sandbox／USER_SCRIPT world 的腳本能不能用 WASM，取決於它設定的 world CSP。
  - userscript 不能從擴充功能的 URL 載入 wasm，要用 `@resource` 或內嵌 base64。在頁面 context 裡 `fetch` 也會受 `connect-src` 限制。
- **iOS Userscripts App（Safari）**：完全是推論。它是 Safari Web Extension，腳本由 content script 注入，有 `@inject-into` 可以選。Safari 的 content script 會不會受頁面 CSP 影響、能不能用 `wasm-unsafe-eval`，都要在實機上驗證。保險起見，**iOS 預設使用 wasm2js 版本**（一般 JS，一定能跑），代價是 1.4 MB 的腳本在行動裝置上的載入時間和記憶體。
- 建議：userscript 版預設 `@inject-into content` 加 WASM，失敗時改用 wasm2js。hook 剪貼簿的部分還是得放在 page context，跟擴充功能的 MAIN／isolated 分工一樣。

## Phase 3 建議架構

```
MAIN world（document_start, all_frames, match_about_blank）
  hook: Clipboard.writeText / write、DataTransfer.setData、copy(capture)
    │  CustomEvent（同步，detail 為 JSON 字串）
    ▼
isolated content script ── WASM 引擎（主力；不受頁面 CSP、不需 extension CSP）
    │  runtime.sendMessage（非同步，只用在非熱路徑）
    ▼
background（Chrome SW / Firefox event page，CSP 加 'wasm-unsafe-eval'）
  規則更新與簽章驗證、設定、Tier-2 LLM、統計
  剪貼簿覆寫退路：Chrome offscreen(CLIPBOARD) execCommand('copy')；Firefox background writeText
```
- **熱路徑**：MAIN 同步問 CS 拿到判定。`copy`／`setData` 當場換掉內容；`writeText` 在 promise 裡等判定。全程不到 1 ms，也不需要 SW。
- **退路**：CS 的 WASM 初始化失敗，或還沒初始化完就有人寫剪貼簿時，CS 改用 wasm2js（同一套 raw ABI，按需透過 `chrome.scripting.executeScript` 注入，不要每頁都載）。還是不行就走 `optimistic` 加 background 覆寫。
- `manifest` 一定要有 `content_security_policy.extension_pages: "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'"`，以及 `clipboardWrite` 權限。Chrome 另外要 `offscreen`。
- 不要依賴 `window.postMessage` 傳遞（Chrome 會多一個 frame 的延遲，而且頁面能監聽）。

## 風險

- **頁面可以干擾 MAIN↔CS 通道**：`CustomEvent` 是頁面看得到的 DOM 事件，頁面可以偽造 `__pw_req`、監聽 `__pw_res`，或在 capture 階段 `stopImmediatePropagation`。緩解方式：每頁產生隨機事件名稱、在 CS 裡用 closure 保存原生函式、判定結果在 CS 端記錄並交叉比對。這部分需要在 THREAT_MODEL 補一節。
- **繞過 hook**：頁面可以從新建的 iframe 拿到乾淨的 `Clipboard.prototype.writeText`（需要 `all_frames` 加 `match_about_blank`／`match_origin_as_fallback`），也可以在 hook 安裝前先把原生函式存起來（`document_start` 可以緩解）。`navigator.clipboard.write(ClipboardItem)` 這次沒測。
- `hold` 模式如果覆寫失敗，剪貼簿會留著佔位文字。`optimistic` 模式有大約 1 ms 的空窗，加上 6 秒的 activation 限制。
- wasm2js 很大（min 1.4 MB），Firefox eval 一次就要 32–46 ms。不能每頁注入。
- Chrome SW 會被回收，所以不能把狀態放在 SW。offscreen 的 `reasons` 沒有「WASM」這個選項，用 `CLIPBOARD`／`WORKERS` 加上 justification，送審時可能被問。
- 自動化測試靠的是 Playwright 的 Chromium（`--load-extension`）和 Firefox 的 RDP temporary add-on。Chrome 品牌版、Safari／iOS 都沒有實測。
- Userscript 管理器的 world CSP 是管理器自己決定的（Violentmonkey 會放寬），版本更新可能會改變行為。
