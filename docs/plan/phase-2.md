# Phase 2：介接層（CLI、agent hook、MCP、WASM、Python）

> 分支：`feature/phase-2-integration` → PR 到 `dev`
> 前提：Phase 1 完成（`Engine::analyze`、語料全過）
> 參考：`docs/spikes/s1-wasm-size.md`、`s2-wasm-csp.md`、`s7-agent-integration.md`、`docs/THREAT_MODEL.md` T7–T9

## 2.1 範圍

| 元件 | 位置 | 用途 |
|---|---|---|
| CLI | `crates/cli`（執行檔 `paste-warden`） | 掃描、agent hook、MCP server、批次評測 |
| WASM | `crates/wasm` + `packages/core-js`（npm `@paste-warden/core`） | 擴充功能、userscript、網頁、Workers 共用 |
| Python | `crates/py`（`paste_warden`，maturin） | Phase 5 紅隊評測直接 `import` |

## 2.2 共用的 Report JSON（CLI `--json`、MCP、WASM 都用這一份）

```jsonc
{
  "schema": 1,
  "action": "allow" | "warn" | "quarantine",
  "truncated": false,
  "command": {
    "level": "none" | "suspicious" | "malicious",
    "risk_score": 0,                       // 0–100，公式見 detection-rules.md §3.6
    "reasons": [{ "id": "cmd-reason-…", "text": "（已依 locale 翻譯）" }],
    "trace": [{ "kind": "caret" | "backtick" | "concat" | "base64" | …, "text": "…", "preview": "…（機密已遮罩）" }],
    "hosts": ["example.invalid"]
  },
  "secrets": [{ "kind": "national_id", "rule_id": "tw-national-id", "label": "身分證字號",
                "masked": "A12****789", "span_utf16": [3, 10] }],
  "hidden": { "level": "none" | "suspicious", "reasons": [{ "id": "…", "text": "…" }] },
  "wallets": [{ "currency": "btc", "span_utf16": [0, 42] }]
}
```

- **永遠不包含機密原文**：只有遮罩後的字串和位置（P4）。`trace.preview` 也是遮罩後的。
- 位置一律是 **UTF-16**（JS 和 Windows 的慣例）；Rust 內部的 byte offset 只在 `crates/wasm` 和 CLI 換算。
- `text` 依呼叫時指定的 `locale`（`zh-TW` | `en`）用 `paste-warden-i18n` 翻譯。
- 型別定義放在 `packages/core-js/src/types.ts`，也是 MCP 工具輸出的 schema 來源。

## 2.3 CLI：`paste-warden`

| 子命令 | 行為 |
|---|---|
| `scan [FILE\|-] [--json] [--locale zh-TW\|en] [--packs tw,us]` | 分析檔案或 stdin。人看的輸出用顏色和白話說明；`--json` 輸出 §2.2。exit code：0 allow、1 warn、2 quarantine、3 錯誤 |
| `mask [FILE\|-]` | 輸出遮罩後的文字 |
| `hook claude-code` | 讀 Claude Code PreToolUse / UserPromptSubmit 的 stdin JSON，見 §2.4 |
| `hook opencode` | 給 opencode plugin 呼叫，見 §2.4 |
| `hook install <claude-code\|opencode> [--scope user\|project] [--dry-run]` | 寫入設定（合併既有 JSON、先備份、`--dry-run` 只印出差異）；`hook uninstall` 反向移除 |
| `mcp [--profile guard]` | stdio MCP server，見 §2.5 |
| `bench FILE.jsonl` | 每行一個 `{"id", "text"}`，輸出每行的判定與總表（Phase 5 紅隊用） |

- 不讀剪貼簿（CLI 沒有這個功能，避免成為外洩管道）。
- 錯誤訊息不含輸入內容（P3）。
- 實作備註：用法錯誤（clap）也是 exit 3，因為 2 已代表 quarantine。`bench` 每行輸出 `{"id","action","level","risk_score","secrets","hidden"}`，最後一行是 `{"summary":{…}}`；格式錯誤的行寫到 stderr（只有行號）並計入 `errors`。另有 `mcp --print-config <agent>` 印出 MCP 設定片段（MCP 不自動安裝）。

## 2.4 Agent hook（強制防護）

- **Claude Code**：`PreToolUse` matcher 為 `Bash|WebFetch|mcp__.*`，但**排除 PasteWarden 自己的 MCP 工具**（S7 的坑）。
  - Bash：`tool_input.command` 交給 `Engine::analyze`；`quarantine` → `permissionDecision: "deny"`，理由中英雙語；`warn` → `"ask"`（讓使用者確認）；`allow` → 不輸出（不要回 `allow`，以免蓋掉使用者自己的 ask 規則）。
  - 對外請求（WebFetch 的 `url`/`prompt`、Bash 的 `curl -d`、MCP 參數）：偵測到機密 → `deny`。
  - `UserPromptSubmit`：偵測到機密 → `{"decision":"block"}`，提示使用者改用遮罩版。這個行為可關閉。
- **opencode**：產生 V2 plugin（`ctx.tool.hook("execute.before")`），由 plugin 呼叫 `paste-warden hook opencode`，判定擋下時 throw Error。**不能用 V1 寫法**（會靜默失效）。
- **Fail-closed**：hook 內部用 `std::panic::catch_unwind` 加上自己的 timeout（預設 2 秒）；解析失敗、panic、逾時一律 deny（Claude Code 對非 0/2 的 exit code 是 fail-open）。整合測試要覆蓋這三種情況。
- `hook install` 預設 `--scope user`。安裝後印出如何驗證（例如請 agent 執行無害的測試指令）與如何移除。
- 實作備註（偏離與補充，理由見 `docs/integrations/agent-hooks.md`）：
  - matcher 為 `^(Bash|WebFetch|WebSearch|Write|Edit|MultiEdit|NotebookEdit|mcp__(?!paste-warden__).*)$`，hook 內部也再排除自家工具。`Write`/`Edit` 的內容含惡意指令也 deny（S7：先寫 script 再執行）；寫入機密不擋。
  - Bash 含機密時：指令會連網（`curl`、`wget`、`nc`…）→ deny，否則 → ask。
  - 解析失敗、panic、逾時：Claude Code 用 exit 2 加 stderr 理由（不知道事件種類時也能擋）；opencode 輸出 `{"block":true}` 並 exit 2。
  - opencode plugin 沒有 ask：`warn` 在 opencode 放行，只有 deny 會擋。
  - `UserPromptSubmit` 的關閉方式：`hook install --no-prompt-guard`（不安裝該 entry）。

## 2.5 MCP server（分析與解釋，不是防護）

- 只用 stdio（`rmcp` 3.x），不開網路埠。
- `guard` profile（預設）工具，全部唯讀：
  - `analyze { text, locale? }` → §2.2 Report
  - `deobfuscate_trace { text, locale? }` → `{ trace, output_preview }`（遮罩後）
  - `scan_secrets { text, packs? }` → `secrets[]`（只有種類和遮罩）
  - `mask { text }` → 遮罩後的文字
- **沒有讀剪貼簿的工具**（T9）。輸入長度上限 1 Mi 字，超過回錯誤。工具描述寫死在程式裡。
- 實作備註：MCP 的 `structuredContent` 必須是物件，所以 `scan_secrets` 回傳 `{ secrets: [...] }`、`mask` 回傳 `{ masked }`；`deobfuscate_trace` 另有 `capped`；`scan_secrets` 也接受 `locale?`（label 的語言）。超過上限是工具錯誤（`isError: true`）。
- `redteam` profile（`validate_syntax`、`run_benchmark`）在 Phase 5 加入。

## 2.6 WASM：`crates/wasm` + `@paste-warden/core`

```ts
// packages/core-js/src/index.ts
export function init(): Promise<void>;                        // 載入 wasm（或 wasm2js 備案）
export function analyze(text: string, opts?: {
  context?: { sourceKind?: 'browser' | 'terminal' | 'ide' | 'chat' | 'other'; url?: string; app?: string };
  settings?: Partial<Settings>;
  locale?: 'zh-TW' | 'en';
}): Report;                                                   // §2.2
export function mask(text: string, report: Report, locale?: 'zh-TW' | 'en'): string;
export function messages(locale: 'zh-TW' | 'en'): Record<string, string>; // UI 用的 ui-* 字串
export const ENGINE_VERSION: string;
```

- 同步 API（`init` 之後）：S2 證明 MAIN world → content script 的同步 `CustomEvent` 路徑需要同步判定。
- 建置：`wasm-bindgen`（`--target web`），`profile.release-wasm` + `wasm-opt -Oz`；`regex` 用 `default-features = false, features = ["std", "perf"]`（S1）。
- **wasm2js 備案**：S2 發現 wasm-bindgen 的 externref 輸出無法給 wasm2js 轉換。`crates/wasm` 另提供 `raw-abi` feature（C ABI：傳入 UTF-8 指標與長度、回傳 JSON 字串指標），`packages/core-js` 在 `WebAssembly` 不可用時改載入 wasm2js 版本。這部分的 `unsafe`（記憶體配置與指標）只允許在 `crates/wasm`。
- 大小預算：gzip < 1.5 MB（S1 實測約 250 KiB）。CI 檢查。
- 測試：`node --test` 跑一份語料子集（每個 area 取若干筆），確認 WASM 結果與 Rust 相同，UTF-16 位置正確。

## 2.7 Python：`crates/py`

- `paste_warden.analyze(text, locale="zh-TW") -> dict`（§2.2）、`mask(text) -> str`、`deobfuscate(text) -> dict`。
- `maturin develop` 可在 `redteam/` 的 uv 環境安裝；CI 用 `maturin build` 確認能編譯。

## 2.8 完成條件

- [ ] `paste-warden scan / mask / bench` 有整合測試（`assert_cmd` 或直接呼叫）；exit code 符合 §2.3。
- [ ] Claude Code hook：真實 `claude -p` 測試（只用無害指令）能擋下語料裡的一筆 ClickFix 樣本、放行 `echo hello`；fail-closed 三種情況有測試。
- [ ] opencode plugin 實測擋下同一筆樣本。
- [ ] MCP guard profile 四個工具可被 Claude Code 呼叫；輸出不含原文（測試）。
- [ ] `@paste-warden/core`：Node 測試通過；gzip 大小在 CI 檢查；wasm2js 版本能跑同一組測試。
- [ ] `paste_warden`（Python）能 import 並通過 smoke test。
- [ ] 文件：`docs/integrations/agent-hooks.md`、`docs/integrations/mcp.md`（繁中），README 加上連結。
- [ ] CI：新增 `js` job（pnpm、Biome、node 測試、wasm 大小）與 `py` job（maturin build + smoke）。
