# Phase 1：核心引擎

> 分支：`feature/phase-1-core` → PR 到 `dev`
> 前提：Phase 0 完成（語料和 CI 都已就緒）
> 範圍：`crates/core`、`crates/rules`、`rules/`、`locales/`、`xtask corpus run`

分兩段，但仍然是**同一個 PR**：

- **1a 對齊**：通過所有從舊版抽出來的語料。
- **1b 超越**：補上已知缺口，加入新功能。

1a 沒有全部通過之前，不開始 1b。舊的 C# 程式碼只留在 git 歷史裡（Phase 0 刪除前的 commit），需要對照實作細節時用 `git show` 查。

## 1.1 公開 API（草案）

```rust
pub struct Engine { /* 編譯好的 RuleSet + 設定 */ }

impl Engine {
    pub fn new(rules: RuleSet, settings: Settings) -> Self;
    pub fn analyze(&self, text: &str, ctx: &Context) -> Report;
    pub fn masked(&self, text: &str, report: &Report) -> String;   // 貼遮罩版用
}

pub struct Context {
    pub source: Option<Source>,   // App 名稱、Bundle ID、網址、種類（瀏覽器、終端機、IDE、通訊軟體…）
    pub platform: Platform,       // Windows | MacOS | Linux | Android | Ios | Web
    pub packs: Vec<PackId>,       // 個資國家包（universal 一律啟用）
    pub registered: Option<RegisteredSecrets>,  // HMAC 金鑰 + 摘要，由平台層提供
}

pub struct Report {
    pub command: Option<CommandFinding>,  // level、signals、hosts、trace、risk_score
    pub secrets: Vec<SecretFinding>,      // kind、label、span、mask
    pub hidden: Vec<HiddenFinding>,
    pub wallets: Vec<WalletAddress>,      // 給錢包掉包的狀態機用
    pub messages: Vec<Message>,           // { id: "cmd-hidden-window", args } → 交給 Fluent 翻譯
    pub truncated: Truncation,
}
```

- **狀態機**也放在 core，全部是純邏輯，時間由呼叫端傳入：
  - `ClipboardGuardState`：剪貼簿狀態
  - `EntryGuard`：執行入口警告
  - `PasteGuard::decide`：貼上前確認
  - `WalletSwapDetector`：錢包掉包
  - `NotificationThrottle`：通知節流
- `Settings`（serde）定義在 core，所有前端共用同一份 schema。預設值是**嚴格**：攔截指令、貼上前確認也涵蓋個資和 API key；**AI 相關功能全部關閉**。
- **位置一律用 UTF-8 byte offset**。`wasm` crate 負責換成 UTF-16；語料的 `span_utf16` 比對時也做同樣的轉換。

## 1.2 模組對照

| 舊版（C#，查 git 歷史） | Rust（`crates/core/src/`） |
|---|---|
| `ClipboardLimits` | `limits.rs` |
| `CommandNormalizer` | `command/normalize.rs` |
| `CommandDetector`、`DownloadExecution` | `command/signals.rs`、`command/download_exec.rs`、`command/verdict.rs` |
| `CommandExplainer` | `command/explain.rs`（只輸出訊息 ID） |
| （新增） | `command/deobfuscate/`：每一層一個檔案，產出 `Vec<DeobfuscationStep>` |
| `SecretTextNormalizer` | `secret/normalize.rs`（附位置對照表） |
| `SecretRules`、`SecretDetector` | `secret/engine.rs`；規則格式放在 `crates/rules` |
| `Checksums` | `secret/checksum.rs`（tw-id、tw-ubn、luhn、各國包的檢查碼） |
| `SecretMasker` | `secret/mask.rs` |
| `RegisteredSecretStore` 的比對 | `secret/registered.rs`（HMAC 滑動視窗、常數時間比較）；儲存在 Phase 4 |
| `HiddenCharDetector` | `hidden.rs` |
| `WalletAddress`、`WalletSwapDetector` | `wallet/` |
| `ExecutionEntryGuard`、`ClipboardGuardState`、`PasteGuard`、`NotificationThrottle` | `policy/` |
| `Verdict` | `report.rs` |
| `tools/convert-gitleaks.mjs`、`build-extension-rules.mjs` | `xtask rules gitleaks`；擴充功能改用 WASM 後就不需要第二份規則 |

## 1.3 規則資料化

- `rules/secrets/*.json`：沿用 format 1（舊版已經避開 lookaround，Rust `regex` 可以直接用），升級成 format 2。新增 `validate` 種類（`luhn`、`tw-id`、`tw-ubn`、`bip39`…）和 `pack` 欄位。
- `rules/command/*.toml`：已知程式清單、官方安裝網站清單、誘餌註解關鍵字（多語系）、LOLBin 參數規格、可執行的副檔名。**結構性的判斷**（下指令的位置、管線、變數代入）留在程式碼裡。
- `crates/rules` 在載入時驗證所有規則：regex 可以編譯、`id` 不重複、沒有長得像真 key 的字串。編譯好的 RuleSet 用 `build.rs` 嵌入執行檔。
- 規則包簽章（ed25519）只先定好格式，實際驗證在 Phase 3 擴充功能更新規則時實作。

## 1.4 1a：對齊

- `cargo xtask corpus run`：用 Rust 跑每一筆語料，和 `expect` 比對，輸出失敗報表（`cargo test` 也會跑同一套）。
- 每一筆失敗只有兩種處理：
  - 修正 Rust
  - 確定舊的預期本身不對，或是刻意改變行為時，寫進 `corpus/divergences.toml`：
    ```toml
    [[divergence]]
    id = "secret.card.017"
    kind = "bugfix"        # bugfix | intentional | legacy-js | unicode-count
    reason = "舊版把 …"
    ```
- 舊版的 C# 和 JS 對同一個輸入的預期不同時（`docs/spec/detection-rules.md` §7），以 C# 為準，JS 那一筆標成 `legacy-js`。
- 長度上限：舊版用 UTF-16 code unit 計算，Rust 改用 `char`。邊界上的差異標成 `unicode-count`。

## 1.5 1b：超越

每一項都要：

- 加上正、負語料
- 更新 `docs/spec/detection-rules.md`
- **良性語料的誤報數不能增加**

| 項目 | 內容 |
|---|---|
| 解混淆 | PowerShell 反引號、字串串接（`'ms'+'hta'`、`& (...)`）、`-join`、`-f`、`-replace`、`[char]` 陣列、`[string]::Concat`、`FromBase64String`、`-enc` 完整解碼；cmd 的 `%x:~a,b%` 子字串、多層變數代入；URL decode、hex；全形英文字母。**最多 5 層，解碼後最多膨脹 4 倍，總長最多 1 Mi** |
| 洋蔥 trace | 每一層記錄 `kind`、這層改了什麼、預覽（截斷）。trace 內容由 UI 跳脫後顯示，裡面的機密要遮罩 |
| 舊版的已知缺口 | `docs/spec/detection-rules.md` §3.4、§5.2 逐項處理：修掉，或註明保留的理由 |
| macOS、Linux 指令 | `osascript -e`、`base64 -d \| sh`、`bash -c "$(curl …)"`、`xattr -d com.apple.quarantine` / `xattr -c`、`chmod +x` 搭配 `/tmp` 執行 |
| Windows 補強 | msiexec 直接安裝遠端套件、`Invoke-Command`、`.Invoke()`、下載 DLL 後用 rundll32 載入 |
| 情境加權 | 來源是瀏覽器時提高 `risk_score`；來源是終端機或 IDE 時降低 Suspicious 的提醒頻率。**情境不能把 Malicious 降級**（P1） |
| 新的機密類型 | BIP-39 助記詞（12、15、18、21、24 個字，**要驗證 checksum**）；含帳號密碼的資料庫連線字串（`postgres://user:pass@`…） |
| gitleaks | 重新加入舊版因為 JS 會變成 O(n²) 而沒收的 `curl-auth-header`、`curl-auth-user` |
| `risk_score` | 0–100，由訊號推算出來，給 UI 和報表用。**判定結果仍然以離散的判定表為準**，維持可解釋性 |

## 1.6 品質要求

| 種類 | 內容 |
|---|---|
| 單元測試 | 每個模組都要有，包含命中和不命中 |
| 語料測試 | `cargo test` 會跑全部語料，並套用 `divergences.toml` |
| proptest | 遮罩結果不包含機密原文；位置對照表的範圍落在 char 邊界上；正規化跑兩次結果不變；解混淆的層數和長度不超過上限；`analyze` 的結果是固定的（同樣輸入，同樣輸出） |
| fuzz（`cargo-fuzz`） | 涵蓋 `analyze`、命令正規化、機密正規化、解混淆、`masked`、規則載入。CI 每個 target 跑 60 秒，用 nightly，放在獨立的 job |
| 效能（criterion） | 一般 1 KB 輸入 ≤ 1 ms；1 Mi 字的病態輸入（所有關鍵字都出現）≤ 150 ms；每條規則的病態輸入 ≤ 50 ms。CI 只有在超過預算 2 倍時才失敗 |
| WASM | `cargo build --target wasm32-unknown-unknown` 必須通過 |

## 1.7 完成條件

- [ ] `xtask corpus run`：失敗數為 0（不算 `divergences.toml` 裡的項目），而且每一筆 divergence 都有 `reason`。
- [ ] 1b 的每一項都完成，或在本文件中註明延後的理由。
- [ ] 良性語料的誤報數不超過 1a 完成時的數字。
- [ ] proptest、fuzz smoke、效能預算、WASM 編譯都在 CI 通過。
- [ ] `docs/spec/detection-rules.md` 裡的程式位置全部改成指向 Rust 模組。
- [ ] `locales/zh-TW`、`locales/en` 涵蓋 core 輸出的所有訊息 ID（由測試檢查）。

## 1.8 已定案

- `risk_score` 的計算公式公開在文件網站上。
- 個資包沿用舊版已有的全部：`universal`、`tw`、`us`、`cn`、`hk`、`jp`、`kr`、`sg`（`rules/pii-*.json`）。預設依裝置地區啟用，台灣使用者預設是 `universal` + `tw`。
