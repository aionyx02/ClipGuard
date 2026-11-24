# corpus：與語言無關的測試語料

這裡的語料是 PasteWarden 行為的**驗收標準**。舊版 C# 與插件的全部測試案例都轉換成這裡的格式（Phase 0），Rust 版必須全部通過（Phase 1）。

```
corpus/
├── README.md                  # 本文件：格式定義
├── legacy-index.json          # 舊版每一個測試案例的 id（自動產生，不要手改）
├── legacy-properties/*.jsonl  # 不適合變成資料案例的舊測試：改成「性質要求」或標成過時
├── divergences.toml           # 刻意與舊預期不同的案例（Phase 1 起）
├── cases/<area>.jsonl         # 案例；每行一筆 JSON
├── ops/<area>.md              # 每個 op 的參數與 expect 欄位定義
└── benign/*.jsonl             # 良性語料：量測誤報率用，不是硬性斷言
```

## 1. 案例格式（`cases/*.jsonl`）

一行一筆 JSON 物件：

| 欄位 | 必填 | 說明 |
|---|---|---|
| `id` | ✅ | 全域唯一、永遠不改。小寫，`<area>.<主題>.<流水號或簡述>`，例如 `command.bypass.caret-001` |
| `area` | ✅ | `command`、`secret`、`hidden`、`wallet`、`entry`、`guard`、`throttle`、`paste`、`registered`、`limits`、`pastejack`、`i18n`、`checksum` 其中之一 |
| `op` | ✅ | 要執行的動作，例如 `command.analyze`。每個 op 的定義寫在 `ops/<area>.md` |
| `source` | ✅ | 來源。舊測試寫 `legacy:<legacy-index 的 id>`，例如 `legacy:tests/ClipGuard.Core.Tests/CommandDetectorTests.cs#ClickFix樣本判為惡意[0]`。新增的案例寫 `new` |
| `input` | 依 op | 主要輸入文字，型別是 [Text](#2-text-型別) |
| `args` | 依 op | 其他參數（物件），例如 `{"packs": ["tw"]}`。裡面的文字欄位也可以用 Text |
| `events` | 依 op | 有時間或狀態的案例：事件陣列，例如 `[{"t_ms": 0, "copy": "…"}, {"t_ms": 400, "copy": "…", "expect": {…}}]` |
| `expect` | ✅ | 預期結果（物件）。**只寫原測試有檢查的欄位**，不要自己補 |
| `tags` | | 字串陣列，例如 `["clickfix", "obfuscation"]` |
| `note` | | 說明，例如原測試的註解 |

- 一個舊測試案例可以拆成多筆語料，`source` 都指向同一個 id。
- 多個舊測試檢查同一件事時，可以各自保留，也可以合併成一筆；合併時，其餘的舊 id 在 `legacy-properties/` 寫一筆 `covered`。

## 2. Text 型別

所有「文字」欄位都可以是下面任何一種，可以遞迴組合：

| 寫法 | 意思 |
|---|---|
| `"abc"` | 字面文字。JSON 的 `\uXXXX` 用來寫零寬字元等看不見的字 |
| `{"parts": [Text, …]}` | 依序串接。**惡意指令一定要拆成片段**，例如 `{"parts": ["power", "shell -w hid", "den …"]}` |
| `{"rand": {"seed": 26, "charset": "hex", "len": 32}}` | 用固定種子產生的假亂數字串，給假 API key 用。可加 `"skip": n`：先丟掉 n 個字元（重現舊測試同一個 `Gen` 連續產生的第二、三個字串） |
| `{"repeat": {"text": Text, "count": 100000}}` | 重複，給長度或效能案例用 |

`rand` 的演算法（Rust、JS、Python 必須產生相同結果）：

```
state = seed (u32)
每個字元：state = (state * 1103515245 + 12345) & 0x7fffffff   // u32 wrapping 乘法
          ch    = charset[(state >> 8) % charset.len]
```

| `charset` | 內容 |
|---|---|
| `hex` | `0123456789abcdef` |
| `HEX` | `0123456789ABCDEF` |
| `alnum` | `A–Z a–z 0–9`（依此順序） |
| `lower` | `a–z 0–9`（依此順序） |
| `upper` | `A–Z 0–9`（依此順序） |
| `digits` | `0123456789` |
| `base64` | `A–Z a–z 0–9 + /` |
| `base64url` | `A–Z a–z 0–9 - _` |
| 其他字串（長度 ≥ 2、不是上面的名稱） | 直接當作字元集 |

## 3. 安全規範（`xtask corpus lint` 會檢查）

- **API key 不能完整寫成字面文字**：一律用 `parts` 或 `rand` 組合，否則會被 GitHub push protection 擋下。例外：廠商公開的範例 key（例如 AWS 文件的 `AKIAIOSFODNN7EXAMPLE`）也要拆開。
- **惡意指令不能完整寫成字面文字**：執行程式名稱（`powershell`、`mshta`…）要和危險參數或下載網址分在不同片段。
- 網址一律用 `example.invalid`（或它的子網域）。
- 個資只用自己算出能通過檢查碼的假號碼，或發卡機構公開的測試卡號。

## 4. 位置

`expect` 裡的位置一律用 **UTF-16 code unit**，寫成 `span_utf16: [起點, 長度]`，和舊版的 `Index`、`Length` 一致。Rust 內部用 UTF-8 byte offset，比對時再換算。

## 5. `legacy-properties/*.jsonl`

不適合變成「輸入 → 預期」的舊測試（例如規則檔載入、效能上限、資源檔完整性、DPAPI），寫在這裡（檔名依 area 分），每行一筆：

```jsonc
{"source": "legacy:…#方法", "disposition": "property", "requirement": "每條規則在 1 Mi 字的病態輸入下 ≤ 50 ms"}
{"source": "legacy:…#方法", "disposition": "obsolete", "reason": "測 DPAPI；新版改用 OS keyring，由 Phase 4 平台層測"}
{"source": "legacy:…#方法[3]", "disposition": "covered", "by": "command.bypass.caret-001", "reason": "與另一筆重複"}
```

- `property`：Rust 版要另外寫測試滿足這個要求（Phase 1 或後面的 Phase）。
- `obsolete`：舊實作特有的細節，新架構不需要；必須寫理由。
- `covered`：已經由其他語料涵蓋。

## 6. 良性語料（`benign/*.jsonl`）

格式同案例，但 `expect` 固定是 `{"clean": true}`，用來**量測誤報率**（不是硬性斷言）。Phase 1 的要求是誤報數不能增加。
