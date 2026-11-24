# PasteWarden 重寫路線圖

> 狀態：草案，待小組確認。發表日期 2026-12-08 ～ 12-15，現場使用 Windows。

## 1. 目標

一份 Rust 偵測核心，編譯到每一個平台，並讓 AI agent 實際參與攻防：

1. **盾**：Windows、macOS、Linux 桌面程式，Android App，Chrome、Edge、Firefox 擴充功能，以及 userscript（Tampermonkey、Violentmonkey、iOS Userscripts）。
2. **保護 AI agent**：提供 Claude Code / opencode 的 hook 和 MCP server，agent 執行指令或送出資料前先經過 PasteWarden。
3. **矛**：紅隊 agent 產生繞過變體，藍隊 agent 修補規則；用量化指標證明防禦有變強。
4. **舞台**：繞過競技場（台下觀眾即時參與）、洋蔥剝皮視圖、無害的靶頁。

**驗收底線**：舊版所有功能都要保留。功能清單以 Phase 0 從舊測試抽出來的語料為準（`corpus/legacy-index.json`），包含已合併的 PR #35：中英文介面，以及 universal、台灣、美國、中國、香港、日本、韓國、新加坡的個資包（規則本來就是資料檔，沿用成本低）。

## 2. 已定案的決策

| 項目 | 決定 |
|---|---|
| 語言 | 核心與平台層用 Rust；UI 用 TypeScript；紅隊用 Python |
| 桌面與行動 | Tauri v2（Windows、macOS、Linux、Android）。**不上架 Apple**，iOS 靠 userscript 和 PWA |
| 擴充功能 | WXT（Chrome、Edge、Firefox）。**不上架 Chrome Web Store**：提供 zip 和安裝說明；Firefox 用 AMO unlisted 免費簽章 |
| userscript | vite-plugin-monkey，輸出單一 `.user.js` |
| 前端 | React + TypeScript + Tailwind；注入網頁的 UI 用 Preact 或原生 JS 加 Shadow DOM |
| 外觀 | 跟隨系統深淺色，可手動切換 |
| 語言 | 繁中、English；跟隨裝置語言，可手動切換；字串用 Fluent |
| 預設嚴格度 | **嚴格**（高風險指令清空剪貼簿、貼上機密前確認），使用者可以逐項調整 |
| 擴充功能與桌面互通 | 用 Native Messaging；只裝其中一個也要完整運作 |
| **AI 功能** | **預設全部關閉**。預設只用本機的 Tier 1 引擎防禦；LLM 解說、agent hook、MCP 由使用者自己開啟或安裝 |
| LLM | 開啟之後可以選：OpenAI 相容（OpenRouter、Ollama、LM Studio、OpenAI、Gemini、Groq…）或 Anthropic 原生，本機和雲端都支援 |
| `risk_score` | 計算公式公開在文件網站上，不靠隱匿保護 |
| Repo | `aionyx02/paste-warden`，公開，MIT 授權 |
| 流程 | `feature/*` → `dev` → `main`；**每個 Phase 一個 PR**；英文 conventional commits |
| 舊版程式 | Phase 0 把測試抽成語料之後，**直接刪除** C# 和舊插件（保留在 git 歷史裡），不維護對照組 |
| JS lint | Biome |
| 競技場網域 | `pastewarden.ntust.org` |
| 文件 | 見 §7 |

## 3. 架構

```
                ┌──────── paste-warden-core（純 Rust，不做 IO）────────┐
                │ normalize → deobfuscate(trace) → signals → score(ctx) │
                │      → Report { verdict, findings, trace, msg ids }   │
                └───▲───────────────────────────────────────────────────┘
                    │ 規則（rules/*.toml|json，可簽章）
  ┌─────────┬───────┴──┬──────────┬──────────┬──────────┬─────────┐
platform    wasm       cli        mcp        py         llm
  │          │          │          │          │          │
Tauri     extension   hook      agents     redteam    Tier-2 解說
desktop   userscript  bench                (PyO3)     （護欄）
android   web / arena-api（Workers）
```

## 4. Repo 結構

```
paste-warden/
├── crates/
│   ├── core/        # 偵測引擎
│   ├── rules/       # 規則格式、載入、驗證、RegexSet 編譯、簽章驗證
│   ├── platform/    # 剪貼簿監聽、前景視窗、貼上 hook、Keychain、Native Messaging
│   ├── llm/         # Provider 抽象與護欄
│   ├── cli/         # paste-warden scan | hook | mcp | bench | rules
│   ├── wasm/        # wasm-bindgen 包裝
│   └── py/          # PyO3 / maturin
├── xtask/           # 開發工具：corpus 對照、規則轉換、發布前檢查
├── apps/
│   ├── desktop/     # Tauri v2（桌面 + Android）
│   ├── extension/   # WXT
│   ├── userscript/  # vite-plugin-monkey
│   ├── web/         # 試玩頁、洋蔥視圖、競技場前端、下載頁
│   ├── docs/        # 使用說明網站（Starlight，中英文）
│   └── arena-api/   # Cloudflare Worker + D1
├── packages/
│   ├── ui/          # 共用 React 元件與 Tailwind 主題
│   ├── core-js/     # WASM 的 npm 包裝 + wasm2js 備案
│   └── i18n/        # 載入 Fluent 字串的共用程式
├── locales/         # zh-TW/、en/ 的 *.ftl（Rust 和 JS 共用）
├── rules/           # 偵測規則（資料）
├── corpus/          # 語料：cases/*.jsonl、benign/、legacy-index.json、divergences.toml
├── redteam/         # Python：產生器、語法驗證、藍隊閉環、報表
├── demo/fake-captcha/  # 無害靶頁，只在 localhost 執行
└── docs/            # 開發者文件：plan/、spec/、spikes/、THREAT_MODEL.md
```

## 5. 平台能力對照

| 功能 | Win | mac | Linux | 擴充功能 | userscript | Android |
|---|---|---|---|---|---|---|
| 背景監看剪貼簿 | ✅ | ✅ 輪詢 | X11 ✅ / Wayland 部分 | 只看網頁內 | 只看網頁內 | ❌ OS 限制 |
| 網頁寫入剪貼簿時攔截 | 搭配擴充功能 | 搭配擴充功能 | 搭配擴充功能 | ✅ | ✅ | Firefox 擴充功能 |
| 執行入口警告 | ✅ | ✅ | X11 | — | — | — |
| 貼上前確認 | ✅ 鍵盤 hook | ✅ 需輔助使用權限 | X11 | ✅ paste 事件 | ✅ | — |
| 個資、金鑰偵測與遮罩 | ✅ | ✅ | ✅ | ✅ | ✅ | 手動檢查（選取文字、分享） |
| 登記機密 | Credential Manager | Keychain | Secret Service | `storage.local` | GM storage | Keystore |
| 錢包掉包 | ✅ | ✅ | ✅ | — | — | — |
| Pastejacking | — | — | — | ✅ | ✅ | Firefox 擴充功能 |

iOS 系統不允許背景讀取剪貼簿，這裡誠實寫出來：iOS 只靠 Safari 的 Userscripts App 和 PWA 試玩頁。

## 6. Phase 規劃

每個 Phase 一個 PR，詳細規格寫在 `docs/plan/phase-N.md`。

| Phase | 內容 | 完成條件 |
|---|---|---|
| **0 地基** | 舊測試抽成語料後刪除 C#；monorepo 骨架、CI；spike 報告 | 語料涵蓋所有舊測試；CI 全綠；每個 spike 都有結論 |
| **1 核心** | core + rules：1a 通過所有舊語料；1b 補上已知缺口、新解混淆、macOS 和 Linux 指令訊號、助記詞 | 語料全部通過，或差異都寫進 `divergences.toml`；fuzz、proptest、效能預算都通過 |
| **2 介接** | cli（scan、hook、bench）、MCP server、Claude Code / opencode hook、wasm、py | Claude Code hook 能擋下靶頁指令；wasm 包大小達標 |
| **3 瀏覽器** | 擴充功能、userscript、web 試玩頁與洋蔥視圖、docs 網站骨架 | Chrome、Firefox、Tampermonkey、iOS Userscripts 都實測通過 |
| **4 桌面** | platform + Tauri：先讓 Windows 和舊版功能完全對等，再做 macOS、Linux、Android；Native Messaging | Windows 手動測試清單（含舊 #9）全部通過 |
| **5 Agent** | llm crate、紅藍隊閉環、四項指標報表、稽核日誌 | 產出 V1 → V3 的偵測率和誤報率圖 |
| **6 發表** | 競技場、靶頁、Release CI、簽章、文件網站、THREAT_MODEL、Demo 影片 | 完整 Demo 腳本能連續成功跑三次 |

Phase 1 完成後，Phase 2 和 3 可以平行；Phase 4 的平台 spike 在 Phase 0 就開始。

## 7. 文件策略

使用說明和技術文件**不全放 README**，但也**不用 GitHub Wiki**。改用 repo 內的文件網站：

| 讀者 | 位置 | 語言 |
|---|---|---|
| 使用者（安裝、功能、FAQ、各平台限制） | `apps/docs`（Starlight），部署到 GitHub Pages | 繁中 + English |
| 開發者（規格、架構、威脅模型、spike 報告） | `docs/`，同時在文件網站的「開發者」區段顯示 | 繁中 |
| README | 一句話介紹、截圖、下載連結、文件網站連結 | 繁中 + English |

不用 Wiki 的理由：Wiki 是另一個 git repo，修改不經過 PR review，不能和程式在同一個 PR 裡更新，也不支援多語系切換。

## 8. 發布與供應鏈

- GitHub Releases 用 `tauri-action` 打包：Windows 的 msi 和 nsis、macOS 的 dmg（ad-hoc 簽章）、Linux 的 AppImage 和 deb、Android 的 apk。
- 擴充功能：Chrome / Edge 提供 zip，Firefox 提供 AMO unlisted 簽章過的 xpi；userscript 放在 GitHub Releases，同時發布到 Greasy Fork。
- 第一個 Release 出來後立刻申請 SignPath Foundation（Windows 免費簽章）。
- **免費的供應鏈防護**：GitHub Artifact Attestations、`SHA256SUMS` + minisign、Tauri updater 簽章、規則包 ed25519 簽章。
- **macOS 安裝說明禁止教使用者貼 `xattr` 指令**，那正是 PasteWarden 要攔的 ClickFix 特徵；只教圖形介面的「強制打開」。
- 遇到 Defender 誤報時，送 Microsoft Security Intelligence 申訴。

## 9. 分工建議

| 人 | 範圍 |
|---|---|
| A | core、rules、fuzz、語料 |
| B | platform、Tauri（桌面 + Android）、Native Messaging |
| C | 擴充功能、userscript、web、docs 網站、競技場 |
| D | llm、cli、MCP、hook、紅藍隊、報表；主講 |

## 10. AI 功能的開關

| 功能 | 預設 | 怎麼開啟 |
|---|---|---|
| Tier 1 本機引擎（全部偵測、遮罩、攔截） | **開啟** | — |
| Tier 2 LLM 解說 | 關閉 | 在設定裡選擇供應商並填入端點或 API key。可以只對高風險指令啟用 |
| Agent hook（Claude Code、opencode） | 不安裝 | 執行 `paste-warden hook install <agent>`，或在設定頁一鍵安裝 |
| MCP server | 不啟動 | 由使用者在 agent 的設定裡加入 `paste-warden mcp` |
| 紅藍隊 | — | 開發和評測工具，不在使用者端的程式裡 |

AI 功能關閉時，程式完全不會連到任何 LLM 端點；這一點要有測試保證。
