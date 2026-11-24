# Phase 0：地基

> 分支：`feature/phase-0-foundation` → PR 到 `dev`
> 目標：
> 1. 把舊版的功能清單轉成跟語言無關的語料，然後刪除 C#。
> 2. 建立 monorepo 骨架和 CI。
> 3. 在動工之前，驗證各平台的技術風險。

## 0.1 前置步驟

- [x] GitHub repo 已改名為 `aionyx02/paste-warden`，本機 remote 也已更新。
- [ ] 本機目錄 `ClipGuard/` 改名為 `paste-warden/`。
- [ ] 啟用 GitHub Pages（來源選 GitHub Actions）。
- PR #35（integrate/wave4）已經合併進 `dev`，所以舊測試也包含國家個資包和中英文介面，一併抽成語料。

## 0.2 語料（corpus）：一次性抽取，抽完就刪 C#

舊版大約 930 個測試案例，就是「至少保留原本功能」的完整清單。**只抽這一次**：輸入和預期結果直接從測試的斷言讀出來，**不執行 C#**。

### 步驟

1. 寫一個一次性的解析腳本，掃描舊的 `tests/**/*.cs` 和 `extension/test/*.js`，把每個測試案例列成 `corpus/legacy-index.json`，格式是 `檔案#方法[第幾筆]`。這份清單會留在 repo 裡，即使原始檔刪除了，也能拿來檢查涵蓋率。
2. 由 Claude Code 逐個測試檔，把案例轉成 `corpus/cases/*.jsonl`。
3. 執行 `cargo xtask corpus coverage`：`legacy-index.json` 裡的每一筆，都必須在語料中找到對應的 `source`，遺漏數必須是 0。
4. **刪除** `src/`、`tests/`、`ClipGuard.sln`、`extension/`、`tools/`，以及舊的 CI workflow（`only-from-dev` 保留）。這些都還留在 git 歷史裡。
5. `docs/detection-rules.md` 移到 `docs/spec/detection-rules.md`。`rules/` 留在原位，給新版使用。

### 格式

完整定義見 [`corpus/README.md`](../../corpus/README.md)（案例欄位、Text 型別、`rand` 演算法、安全規範）與 `corpus/ops/*.md`（每個 op 的參數與 `expect`）。

### 需要額外補的良性語料（量測誤報率用）

| 檔案 | 內容 | 數量 |
|---|---|---|
| `corpus/benign/dev-commands.jsonl` | 官方安裝指令、git、docker、npm、cargo、kubectl、常見的 PowerShell 管理指令 | ≥ 300 |
| `corpus/benign/numbers.jsonl` | 日期、訂單編號、IP、版本號、發票號碼、郵遞區號、表格 | ≥ 300 |
| `corpus/benign/text.jsonl` | 中英文句子、程式碼、minified JS、Base64 圖片（沿用 `secret-false-positives.json`） | 全部沿用 |

### 檢查：`cargo xtask corpus lint`

- `id` 不能重複，每一筆都要通過 JSON schema。
- **掃描整個 repo**：不能出現完整的 API key 或完整的惡意指令字串（沿用舊版 `SecretRulesTests` 的掃描邏輯）。
- 每個 `area` 都要同時有正樣本和負樣本。

## 0.3 Monorepo 骨架

- `Cargo.toml` workspace：建立 roadmap §4 列出的所有 crate。內容先是空殼，但要能編譯。用 `rust-toolchain.toml` 固定 stable 版本，加上 `wasm32-unknown-unknown` target。
- `pnpm-workspace.yaml`、根目錄的 `package.json`，lint 用 **Biome**。
- `xtask`：`corpus lint | coverage`。
- `locales/zh-TW/`、`locales/en/`：放 Fluent 檔案骨架。
- `.editorconfig`、`.gitattributes`（`corpus/**` 一律用 LF）。
- README 改成新品牌的骨架：PasteWarden、標示「重寫中」、連到 roadmap。

## 0.4 CI（`.github/workflows/`）

| Job | 內容 |
|---|---|
| `rust` | ubuntu、windows、macos：fmt、clippy `-D warnings`、test |
| `wasm` | core、rules、wasm 三個 crate 要能編譯到 `wasm32-unknown-unknown` |
| `corpus` | `xtask corpus lint` 和 `coverage` |
| `build-test` | 彙總：上面全部成功才算通過。名稱和舊版相同，branch ruleset 的必要檢查不用改 |
| `only-from-dev` | 沿用 |

JS 的 Biome 檢查等 Phase 3 有前端程式碼時再加入 CI。

## 0.5 Spike

每個 spike 寫一份報告到 `docs/spikes/<name>.md`，內容包含：結論、數據、遇到的坑、建議做法。Spike 的程式**不合併**，留在各自的分支。

| # | 題目 | 要回答的問題 | 負責 |
|---|---|---|---|
| S1 | WASM 大小與速度 | `regex` 加上全部規則編成 WASM 有多大（目標 gzip < 1.5 MB）？初始化和分析 1 Mi 字各要多久？ | A |
| S2 | CSP 下的 WASM | 在 CSP 嚴格的網站上，擴充功能（content script、MAIN world、offscreen）和 userscript 能不能編譯 WASM？Chrome 和 Firefox 都要測。wasm2js 備案的大小和速度如何？ | C |
| S3 | Windows 監聽 | 在 Tauri 裡用 Rust 實作剪貼簿監聽、鍵盤 hook、前景視窗；Defender 會不會誤報？ | B |
| S4 | macOS 監聽 | objc2 輪詢 `changeCount`、Concealed type、CGEventTap 的授權流程 | B |
| S5 | Linux | X11（XFixes）和 Wayland（`wlr-data-control`）各能做到什麼程度？ | B |
| S6 | Android | Tauri v2 的 Android 能不能接 `PROCESS_TEXT` 和分享 intent？ | B |
| S7 | Agent 介接 | `rmcp` MCP server，以及 Claude Code PreToolUse hook、opencode plugin 的最小可行版本 | D |
| S8 | 語法驗證 | `pwsh` 的 `Parser::ParseInput` 在 macOS 和 Linux 上能不能用、速度如何？cmd 有什麼替代方案？ | D |
| S9 | Native Messaging | Chrome 和 Firefox 的 host manifest 怎麼安裝、怎麼發現對方、怎麼互相驗證身分 | B、C |

## 0.6 完成條件

- [ ] `corpus/legacy-index.json` 涵蓋舊版所有的 C# 和 JS 測試案例；`xtask corpus coverage` 的遺漏數為 0。
- [ ] 良性語料各類達到規定數量。
- [ ] C# 和舊插件已刪除，CI 全綠。
- [ ] S1–S9 都有報告；有 ❌ 的項目已經更新到 roadmap 的平台能力對照表。
- [ ] 完成 `docs/THREAT_MODEL.md` 初版：要防的威脅、不防的範圍、信任邊界。
