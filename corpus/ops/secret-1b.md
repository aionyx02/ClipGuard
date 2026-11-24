# secret（phase 1b 補充）

Phase 1b 沒有新增 op，也沒有新增 expect 欄位；`secret.find`、`secret.mask_text`、`i18n.localized` 照原本的定義（`secret.md`、`i18n.md`）。這裡只記錄新增的值。

## 1b 新增的 kind 與標籤

- `kind` 多一個 `mnemonic`（錢包助記詞，`docs/spec/detection-rules.md` §5.7）。
- 助記詞的 `label` 帶字數：zh-TW「錢包助記詞（12 個字）」、en「Wallet recovery phrase (12 words)」；`masked` 是 `******** (12)`。
- 資料庫連線密碼（§5.8）的 `kind` 是 `api_key`，`label`「資料庫連線密碼」，`masked` 只有星號（最多 8 個）。
- gitleaks 的 curl 規則沒有翻譯，`label` 是規則檔裡的 `Curl auth header`、`Curl auth user`。

## 1b 語料檔

| 檔案 | 內容 |
|---|---|
| `cases/secret-1b-mnemonic.jsonl` | 助記詞：12–24 個字、編號清單、逗號、大寫、夾在中英文句子裡、貼遮罩版、英文標籤；11／13／25 個字、checksum 錯、都是清單單字的英文句子、`-` 或句點連接 |
| `cases/secret-1b-connection-strings.jsonl` | URL 與 ODBC／ADO.NET／JDBC 形式、只遮密碼；佔位字、預設帳密、沒有密碼 |
| `cases/secret-1b-curl.jsonl` | `curl -u`、`curl -H` 的 Basic／沒寫 scheme／自訂標頭；Bearer 仍由第 2 層標示；變數與佔位字 |
| `cases/secret-1b-context-cjk.jsonl` | 中日韓的金鑰名稱（密碼、金鑰、密钥、パスワード、비밀번호、權杖）；值不像金鑰或沒有名稱 |
| `cases/secret-1b-placeholders.jsonl` | `sk_test_xxxx…` 佔位字不算（`benign.text.083`）；真的亂數、中間夾一段 x 的照樣算 |

助記詞語料用固定的 entropy（`SHA-256("paste-warden corpus bip39 <n>")` 的前幾個 byte）算出來，不是真的錢包；整串拆成兩個 `parts` 存。
