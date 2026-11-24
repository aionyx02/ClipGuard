# S1 WASM 大小與速度

> 狀態：完成（2026-11-24）。拋棄式 crate 放在 scratchpad（不進 repo）；這份是唯一產出。

## 結論

- **大小達標，而且還有很多餘裕。** 226 條 regex 規則（`rules/*.json` 全部，加上 22 條 exclude）全部編譯，用 `regex` 1.13.2 的完整預設 features 時，`wasm-opt -Oz` 之後是 **gzip 338 KiB／brotli 243 KiB**。關掉 `unicode*` features 之後是 **gzip 250 KiB／brotli 198 KiB**，速度一樣。目標是 gzip < 1.5 MB。
- **初始化**：一次把所有規則編譯好，Node 裡要 30 ms（中位數），第一次 53 ms。改成「規則等到關鍵字出現才編譯」（lazy）之後是 **2 ms（第一次 8 ms）**，記憶體也從 11 MB 降到 1.8 MB。
- **分析**：1 KB 的真實文字約 0.03 ms（第一次 3 ms，lazy DFA 快取要暖機）。1 Mi 字的病態輸入要 **約 200 ms**，是原生的 **~10 倍**。原因是 wasm 沒有 Teddy 和 SIMD memmem 這些 literal prefilter：原生版關掉 `perf-literal` 之後要 267 ms，比 wasm 還慢。開 `simd128` 只快了約 7%。
- **build time 預先編譯 DFA 不值得做。** 14 條沒有關鍵字的規則合成一個 dense DFA，超過 256 MB 還沒建完；226 條全部合也一樣。拆成每條一個 DFA 雖然做得出來（sparse 391 KB／gzip 53 KB），但安全的 `from_bytes`（有檢查）要 1.9 ms，比直接建 `RegexSet` 的 1.2 ms 還慢。不檢查的版本要用 `unsafe`，但 workspace 是 `unsafe_code = "deny"`，core／rules 還是 `#![forbid(unsafe_code)]`。

## 測試方式

- 環境：Apple M5 Max（arm64）、rustc 1.100.0、Node 26.8.1、`wasm-bindgen` 0.2.130（CLI 同版本）、binaryen `wasm-opt` version 132、`gzip -9`、`brotli -q 11`。
- crate 版本：`regex` 1.13.2、`regex-automata` 0.4.19、`regex-syntax` 0.8.12、`aho-corasick` 1.1.5（`default-features = false, features = ["std"]`）、`memchr` 2.8.3、`serde_json` 1.0.154。
- profile：`[profile.release-wasm]` 跟 repo 的一樣（`inherits = "release"`、`lto = true`、`codegen-units = 1`、`opt-level = "z"`、`panic = "abort"`）。原生版用 `release`（opt-level 3）。
- 引擎（模擬真的會怎麼寫）：
  - `include_str!` 把 11 個 JSON 內嵌進去，init 時用 `serde_json` 解析。
  - 每條規則各一個 `regex::bytes::Regex`，設 `unicode(false)` 和 `case_insensitive(ignoreCase)`。比對的是 §5.4 的「ASCII 版本」：非 ASCII 字元換成 0x1A，所以 `\b` 和不分大小寫只認 ASCII，跟 JS 一樣；`$` 預設就是整段結尾。
  - 沒有關鍵字的 14 條規則另外合成一個 `RegexSet`，每條規則的 `ignoreCase` 由引擎在內部包成 `(?i:…)`。
  - 241 個關鍵字放進一個 `AhoCorasick`（`ascii_case_insensitive`）做預先篩選。
  - `analyze` 依序做：轉 ASCII 版本 → 找出出現的關鍵字 → `RegexSet.matches` → 對每條啟用的規則跑 `captures_iter`，回傳群組數。
- 輸入：`real1k`（1 KB 的中英混合 .env 和對話，17 個群組命中）；`kw1m`（241 個關鍵字用空白連接，重複到 1,048,576 字，所有規則都會啟用但沒有命中）；`assign1m`（`<關鍵字>_key = "<40 字 base64>"` 一直重複，2605 個命中）；`a1m`（1 Mi 個 `a`，沒有關鍵字）。
- 計時：init 和 1 KB 的分析取中位數（init 跑 5 次、1 KB 跑 200 次），1 Mi 跑 5 次取中位數。「第一次」另外列。wasm 是 `wasm-bindgen --target nodejs`，用 `performance.now()` 量。記憶體是 `memory.size × 64 KiB`。

## 數據

### 大小（bytes；wasm-bindgen 之後 → `wasm-opt -Oz`）

| 變體（`regex` features；除非另外註明，都用 `opt-level="z"`） | raw | `-Oz` | gzip | brotli |
|---|---:|---:|---:|---:|
| A `default`（std＋perf＋unicode） | 1,467,266 | 999,184 | 345,643 | 248,591 |
| **B `std,perf`（不含 unicode）** | 1,157,532 | 688,863 | **255,612** | 202,358 |
| C `std,perf,unicode-case,unicode-perl` | 1,242,834 | 772,545 | 290,592 | 223,990 |
| D `std`＋perf 但不含 `perf-literal` | 1,093,254 | 653,939 | 243,964 | 193,360 |
| E `std`＋perf 但不含 `perf-dfa` | 1,000,479 | 576,414 | 212,540 | 174,271 |
| F `std`（什麼 perf 都不開） | 894,029 | 513,596 | 188,502 | 156,671 |
| B＋`-C target-feature=+simd128` | 1,155,719 | 686,901 | 255,660 | 202,803 |
| B＋`opt-level=3` | 1,078,356 | 844,529 | 309,182 | 240,295 |
| B＋`opt-level="s"` | 1,059,538 | 706,224 | 259,538 | 207,587 |
| B＋lazy 編譯 | 1,159,163 | 689,641 | 255,844 | 202,541 |

說明：內嵌的規則 JSON 是 96 KB（壓縮後大約 15 KB）；`serde_json` 也在 binary 裡面。unicode 表大約佔 90 KB gzip（A − B）。

### 速度（ms；中位數，括號裡是第一次）

| 變體 | 環境 | init | real1k | kw1m | assign1m | a1m |
|---|---|---:|---:|---:|---:|---:|
| A default | 原生 | 11.9 (13.7) | 0.010 (0.35) | 20.9 | 20.6 | 2.30 |
| A default | wasm | 30.6 (53.4) | 0.033 (3.3) | 204.5 | 221.7 | 6.73 |
| **B std,perf** | 原生 | 11.7 (13.4) | 0.010 (0.36) | 20.7 | 20.1 | 2.59 |
| **B std,perf** | wasm | 30.5 (52.5) | 0.032 (3.2) | 196.3 | 220.1 | 6.70 |
| B＋simd128 | wasm | 30.5 (54.6) | 0.033 (3.2) | 184.1 | 203.7 | 6.67 |
| B＋opt-level=3 | wasm | 19.4 (45.4) | 0.032 (2.9) | 173.0 | 214.6 | 5.17 |
| D 不含 perf-literal | 原生 | 10.5 (12.1) | 0.022 | 267.4 | 275.7 | 2.67 |
| D 不含 perf-literal | wasm | 21.5 (40.1) | 0.042 (3.2) | 372.0 | 381.4 | 6.23 |
| E 不含 perf-dfa | wasm | 18.4 (40.2) | 0.42 (2.6) | 1,135 | 1,043 | 329.5 |
| F 只有 std | wasm | 14.2 (27.1) | 0.77 (2.6) | **7,722** | **7,413** | 270.2 |
| **B＋lazy** | 原生 | 1.2 (2.6) | 0.022 (2.8) | 20.6 (44.5) | 20.2 | 2.49 |
| **B＋lazy** | wasm | **2.2 (8.3)** | 0.032 (7.7) | 193.8 (232.4) | 216.0 | 6.99 |

wasm 跟原生的倍數（變體 B）：init 2.6 倍（第一次 3.9 倍）、real1k 3.2 倍、kw1m 9.5 倍、assign1m 11 倍、a1m 2.6 倍。Node 載入加上編譯 wasm 模組約 1.3 ms。

### 記憶體（wasm linear memory）

| 變體 | init 之後 | 跑完 4 種輸入之後（不會縮回去） |
|---|---:|---:|
| A default | 11.1 MiB | 21.9 MiB |
| B std,perf | 10.8 MiB | 21.6 MiB |
| F 只有 std | 4.3 MiB | 8.2 MiB |
| **B＋lazy** | **1.75 MiB** | 21.1 MiB |

### build time 預先編譯（`regex-automata` 0.4.19，`dfa-build`，`unicode(false)`，`utf8(false)`）

| 做法 | 結果 |
|---|---|
| 14 條沒有關鍵字的規則合成一個 dense DFA（`MatchKind::All`、unanchored、不 minimize） | 12.6 s 後超過 256 MB 上限，失敗（`{2,7}`、`{1,8}` 這類計數重複和電話、身分證規則彼此相乘） |
| 226 條全部合成一個 | 3.1 s 後超過 256 MB，失敗 |
| 每條一個 DFA（每條上限 8 MB） | 175 條成功、51 條失敗；成功的加起來 dense 167 MB／sparse 132 MB |
| 只做那 14 條，每條一個 | dense 571 KB（gzip 47 KB）／sparse 391 KB（gzip 53 KB）；最大的是 CN 身分證（274 KB）和 KR（190 KB） |
| 載入這 14 個 sparse DFA（`from_bytes`，有檢查） | 原生 1.9 ms，對照直接建 `RegexSet` 的 1.2 ms |

另外，forward DFA 只能找到結尾，要拿到開頭得再加一個 reverse DFA（大小再加一倍），捕獲群組還是得靠 NFA。lazy 編譯把 init 從 30 ms 降到 2 ms，DFA 序列化省不了這麼多，大小卻要加 50 KB 以上。

## Phase 2 建議設定

```toml
# crates/rules（或 core）
regex = { workspace = true, default-features = false, features = ["std", "perf"] }
aho-corasick = { version = "1", default-features = false, features = ["std"] }
# [profile.release-wasm] 維持現狀：opt-level="z"、lto、codegen-units=1、panic="abort"
```

- 用 `regex::bytes` 加 `RegexBuilder::unicode(false)`，比對 §5.4 的 ASCII 版本。這樣行為跟 JS／.NET 的子集合一樣，也才可以不開 `unicode*` features（用 `&str` API 搭配 `unicode(false)` 的話，`[^\n]` 這類 pattern 會編譯失敗）。
- 沒有關鍵字的規則用 `RegexSet`。有關鍵字的用 `AhoCorasick` 篩選，每條規則的 `Regex` 放在 `OnceLock` 裡，等到用到才編譯（lazy）。CI／`xtask` 要另外把每條規則都編譯一次，不要等到使用者貼上時才發現 regex 寫錯。
- 建置流程：`cargo build --profile release-wasm --target wasm32-unknown-unknown`，接著 `wasm-bindgen`，最後 `wasm-opt -Oz`。Rust 1.100 預設會開 bulk-memory、reference-types、multivalue 這些 feature，binaryen 132 要加上對應的 `--enable-*`（或用 `--all-features`），不然會驗證失敗。
- 不要開 `simd128`：只快 7%，又多一個相容性條件。`opt-level=3` 快 5–12%、init 快約 35%，但 gzip 多 21%，暫時不值得。
- 不需要 build time 預先編譯 DFA。

## 風險

1. **病態輸入在 wasm 上慢 10 倍**：1 Mi 字、關鍵字很密的時候要 ~200 ms，放在主執行緒上會卡住 UI。插件和網頁版要在 Worker 或 offscreen document 裡跑；第 2 層的篩選也可以先截短文字。
2. **linear memory 只會長不會縮**：跑過 1 Mi 輸入之後停在 ~21 MiB（主要是每條 regex 的 lazy DFA 快取）。每個分頁各載一份的話會累加起來。共用一個 Worker，或是分析完重新建立 instance。
3. **lazy 編譯把成本移到第一次貼上**：real1k 第一次要 7.7 ms，kw1m 第一次要 232 ms，因為命中關鍵字的規則要當場編譯。可以在閒置時預熱。
4. **unicode features 關掉之後**，以後規則如果要用 Unicode 類別，或是 `&str` API 要 Unicode 語意，就得把 `unicode-perl`／`unicode-case` 加回來（gzip 多約 35 KB）。
5. **這次只在 Node（V8）量過**：Firefox（SpiderMonkey）和 Safari 的倍數可能不同，CSP 的部分留給 S2。DFA 序列化只量了原生版，量級夠參考，但不是精確數字。
6. `RegexSet` 只有一組旗標，每條規則的 `ignoreCase` 由引擎在內部包成 `(?i:…)`。這跟 §5.4「規則檔不能寫行內旗標」不衝突，但要留意 `RegexSet` 跟單條 `Regex` 的語意要保持一致。
