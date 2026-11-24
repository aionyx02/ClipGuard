# WASM 與 Python 綁定

> 對應 `docs/plan/phase-2.md` §2.2、§2.6、§2.7。背景數據見 `docs/spikes/s1-wasm-size.md`、`s2-wasm-csp.md`。

PasteWarden 的偵測引擎（`crates/core`）透過三種方式給 Rust 以外的程式用：

| 套件 | 位置 | 給誰用 |
|---|---|---|
| `@paste-warden/core`（npm，ESM） | `packages/core-js` + `crates/wasm` | 擴充功能、userscript、網頁、Node |
| wasm2js 備案（同一個 npm 套件） | `crates/wasm` 的 `raw-abi` feature | 不能跑 WebAssembly 的地方（嚴格 CSP 的 MAIN world、iOS userscript） |
| `paste_warden`（Python，abi3） | `crates/py` | Phase 5 紅隊評測 |

三者共用 `crates/wasm/src/api.rs`，輸出的 Report JSON 一個 byte 都不差（§2.2）。

## JS API

```ts
import { init, analyze, mask, messages, deobfuscate, ENGINE_VERSION } from '@paste-warden/core';

await init();                         // 只要一次；之後全部是同步呼叫
const report = analyze(text, {
  context: { sourceKind: 'browser', url: location.href },  // 只影響 risk_score，不會降低判定
  settings: { packs: ['universal', 'tw', 'us'] },          // 沒寫的欄位用嚴格預設值
  locale: 'zh-TW',                                         // reasons / label 的語言，預設 zh-TW
});
if (report.action !== 'allow') {
  const safe = mask(text, report, 'zh-TW');                // 「貼上遮罩版」
}
const ui = messages('en');            // { 'ui-app-name': 'PasteWarden', … }
```

- 型別在 `src/types.ts`（`Report`、`Settings`、`AnalyzeOptions`…），也是 MCP 工具輸出的 schema 來源。欄位名稱和 Rust／CLI 一樣用 snake_case。
- **位置一律是 UTF-16**：`span_utf16: [起點, 長度]`，可以直接 `text.slice(start, start + len)`。換算在 `crates/wasm` 做。
- **Report 裡沒有機密原文**，只有 `masked` 和位置（P4）。`trace[].preview`、`output_preview` 也已遮罩，但仍是不可信的內容，顯示時要跳脫。
- `mask(text, report)` 的 `report` 必須是同一段 `text` 的 `analyze` 結果；只會用到 `secrets` 的 `kind`、`masked`、`span_utf16`。
- 錯誤（例如 `context.sourceKind` 寫錯）會丟出 `Error`，訊息裡不會有輸入文字。

### `init(options?)`

| 選項 | 說明 |
|---|---|
| `backend: 'auto'`（預設） | 先試 WebAssembly；`WebAssembly` 不存在或編譯被擋（CSP 沒有 `'wasm-unsafe-eval'`）時改載入 wasm2js |
| `backend: 'wasm' \| 'wasm2js'` | 強制使用其中一個（測試用） |
| `wasm` | 自己提供 `.wasm`：`URL`、`Response`、bytes 或 `WebAssembly.Module`。預設是 `new URL('./wasm/paste_warden_bg.wasm', import.meta.url)`，Vite／webpack 會自動處理這個寫法 |

- Node 會自動用 `fs` 讀 `file:` URL。
- 擴充功能：引擎放在 isolated world 的 content script（不受頁面 CSP 影響）。background、offscreen document 要在 `content_security_policy.extension_pages` 加 `'wasm-unsafe-eval'`（S2）。
- wasm2js 版本大（gzip 約 1 MB），而且 import 時就要 eval 整個模組，**不要每頁都載**，只在 WASM 不能用時才動態載入（`init()` 預設就是這樣）。
- 1 Mi 字、關鍵字很密的病態輸入在 WASM 上要幾百 ms（S1），請在 Worker 或 offscreen document 裡跑長文字。

## 建置

需要：Rust（`rust-toolchain.toml` 會裝 `wasm32-unknown-unknown`）、Node ≥ 22、pnpm，以及跟 `Cargo.lock` 裡 `wasm-bindgen` 同版本的 CLI：

```sh
cargo install wasm-bindgen-cli --version 0.2.130 --locked   # 或下載 GitHub release 的執行檔（CI 這樣做）
pnpm install                                                 # 會裝 binaryen（wasm-opt、wasm2js）和 TypeScript
pnpm --filter @paste-warden/core build                       # 產生 packages/core-js/dist/
pnpm --filter @paste-warden/core size                        # gzip < 1.5 MB 檢查
pnpm --filter @paste-warden/core test                        # node --test，WASM 和 wasm2js 各跑一次
```

`scripts/build.mjs` 做的事（中間檔放在 `target/core-js/`）：

1. `cargo build -p paste-warden-wasm --target wasm32-unknown-unknown --profile release-wasm` → `wasm-bindgen --target web` → `wasm-opt -Oz` → `dist/wasm/`。
2. 同一個 crate 用 `--no-default-features --features raw-abi` 再建一次（不經過 wasm-bindgen）→ `wasm-opt -Oz --llvm-nontrapping-fptoint-lowering --llvm-memory-copy-fill-lowering` → `wasm2js` → `dist/wasm2js/`。
3. `tsc` → `dist/*.js`、`*.d.ts`。

wasm-opt／wasm2js 預設用 `binaryen` devDependency（npm 版，JS 實作，比較慢但不用另外安裝）；要用系統上的版本可以設定 `WASM_OPT`、`WASM2JS`、`WASM_BINDGEN` 環境變數。

踩過的坑：
- wasm-bindgen 的輸出用到 externref table，wasm2js 不支援，所以備案走 raw C ABI（S2）。
- `wasm-opt --all-features` 會產生 tail call，wasm2js 不支援，所以要明確列出 feature。
- rustc 會產生 `i64.trunc_sat_f64_u`，wasm2js 把 i64 拆成兩個 i32 之後驗證失敗；要先用 `--llvm-nontrapping-fptoint-lowering` 降級。

### 大小（2026-11-25，macOS arm64，rustc 1.100、binaryen 132）

| 檔案 | raw | gzip -9 | brotli 11 |
|---|---:|---:|---:|
| `dist/wasm/paste_warden_bg.wasm` | 1,406,353 | **557,853** | 434,779 |
| `dist/wasm2js/paste_warden_raw.js` | 6,578,926 | 1,015,152 | 709,875 |

比 S1 的 gzip 250 KiB 大，因為多了完整引擎、Fluent 和兩種語言的字串、Unicode 正規化表，以及 `hidden` 需要的 Unicode 類別。仍遠低於 1.5 MB 的預算。

`regex` 的 features：`hidden` 偵測用到 `\p{L}`、`\p{P}`、`\p{M}`（需要 `unicode-gencat`），規則用到 Unicode 的 `\w`／`\d`／`\s` 和不分大小寫（`unicode-perl`、`unicode-case`）。拿掉任何一個，語料就會失敗（只開 `std,perf` 有 13 個 core 測試失敗；拿掉 `unicode-gencat` 語料 25 筆失敗；拿掉 `unicode-case` 數百筆失敗）。所以 root `Cargo.toml` 設成 `default-features = false, features = ["std", "perf", "unicode-case", "unicode-gencat", "unicode-perl"]`，只拿掉 `unicode-age`、`unicode-bool`、`unicode-script`、`unicode-segment`：wasm gzip 從 599,987 降到 557,874 B（−42 KB），wasm2js gzip 從 1,109,404 降到 1,015,172 B。

## raw C ABI（`crates/wasm/src/raw.rs`）

給 wasm2js（或任何不想用 wasm-bindgen glue 的環境）用。這是 workspace 裡唯一允許 `unsafe` 的模組。

| export | 說明 |
|---|---|
| `memory` | linear memory |
| `pw_alloc(len) -> ptr` | 配置 `len` bytes；呼叫端寫入 UTF-8，用完自己 `pw_free(ptr, len)` |
| `pw_free(ptr, len)` | 釋放 `pw_alloc` 的 buffer 或結果 buffer |
| `pw_analyze(text, text_len, opts, opts_len) -> res` | Report JSON |
| `pw_mask(text, len, report, len, locale, len) -> res` | 遮罩後的文字 |
| `pw_messages(locale, len) -> res` | `ui-*` 字串 JSON |
| `pw_deobfuscate(text, len, locale, len) -> res` | 解混淆 trace JSON |
| `pw_engine_version() -> res` | 版本字串 |

結果 buffer 的格式：`[u32 LE 內容長度][u8 狀態：0 成功、1 錯誤][UTF-8 內容]`，讀完用 `pw_free(res, 5 + 長度)` 釋放。JS 端的 glue 在 `packages/core-js/src/backend.ts`。

## Python：`paste_warden`

```python
import paste_warden

report = paste_warden.analyze(text, 'zh-TW', packs=['universal', 'tw'])  # dict，同 §2.2
masked = paste_warden.mask(text)                                       # str
trace = paste_warden.deobfuscate(text, 'en')  # {'trace': [...], 'output_preview': str, 'capped': bool}
paste_warden.ENGINE_VERSION
```

- `span_utf16` 是 UTF-16 位置（跟 JS 一樣），**不是** Python 的字元索引：BMP 以外的字元（emoji）在 Python 算 1、在 UTF-16 算 2。
- 建置與測試（在 `crates/py`）：

  ```sh
  uv run pytest -q                       # uv 會用 maturin 建置並安裝到 .venv，再跑 tests/
  uvx maturin build --release --out dist # 產生 abi3 wheel（Python ≥ 3.10）
  uvx maturin develop                    # 裝進目前啟用的 venv（例如 redteam/ 的 uv 環境）
  ```

  沒有 uv 的話：`python3 -m venv .venv && .venv/bin/pip install maturin pytest && .venv/bin/maturin develop && .venv/bin/pytest`。
- PyO3 的程式碼放在 `python` feature 後面，預設不編譯，所以 `cargo build／test／clippy --workspace` 不需要 Python 或 libpython。maturin 會開啟 `python` 和 `pyo3/extension-module`（`pyproject.toml`）。CI 的 `py.yml` 另外跑 `cargo clippy -p paste-warden-py --features python`。

## CI

- `.github/workflows/js-core.yml`：raw ABI 單元測試、`raw-abi` 的 wasm32 建置、Biome + tsc、`build`、gzip 大小檢查、`node --test`（WASM 和 wasm2js 都跑同一組測試，包括 1,200 多筆語料）。
- `.github/workflows/py.yml`（Linux／macOS／Windows）：clippy（`python` feature）、`maturin build`、`uv run pytest`。

## 測試涵蓋

`packages/core-js/test/engine.test.mjs` 對兩種建置各跑一次：

- API：ClickFix 判定與 `quarantine`、翻譯後的理由（預設 zh-TW）、情境只影響分數、trace、emoji 在機密前面的 UTF-16 位置、`mask`、隱藏字元、錢包位置、設定、錯誤訊息不含原文、`ui-*` 字串、`ENGINE_VERSION` 與 `Cargo.toml` 一致。
- 語料：`corpus/cases` 裡所有 `command.analyze`、`command.analyze_in`、`secret.find`、`secret.mask_text`、`hidden.analyze`（共 1,211 筆），用跟 `crates/conformance` 相同的比對規則。超過 `MAX_ANALYZED_CHARS`（1 Mi 字）的 4 筆會略過並列出：它們測的是偵測器自己的頭尾掃描，`Engine::analyze` 只讀前 1 Mi 字。
