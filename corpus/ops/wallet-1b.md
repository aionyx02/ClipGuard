# wallet（1b）

1b 沒有新增 op 或 expect 欄位：`corpus/cases/wallet-1b-*.jsonl` 用的是既有的 `wallet.parse`、`wallet.find_all`、
`wallet.swap`（`ops/wallet.md`）。下面是 1b 對它們的規則補充，和 `ops/wallet.md` 不同的地方以這裡為準。

## 幣別列舉（擴充）

`bitcoin` | `ethereum` | `tron` | `solana` | `xrp`

## wallet.parse（1b 補充） 的 1b 規則

依序判斷，第一個成立的就是結果：

1. ETH：`0x`／`0X` + 40 hex。**hex 部分大小寫混用時要通過 EIP-55**（第 i 個字母大寫 ⇔ `keccak256(小寫 hex 的 ASCII)`
   的第 i 個 nibble ≥ 8）；全小寫、全大寫沒有檢查碼，照樣有效。`normalized` 轉小寫（不變）。
2. BTC bech32／bech32m（不變）。
3. Base58Check（1 個版本 byte + 20 bytes + 4 bytes 雙 SHA-256 檢查碼，長度 26–35）：`1…`／`3…` BTC、`T…` TRON（不變），
   以及 **`r…` XRP**（Ripple 字母表 `rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz`，版本 0x00）。
4. **Solana**：長度 32–44、Bitcoin 字母表的 Base58、解碼後**剛好 32 bytes**，而且不是全由 hex 數字（`0-9a-fA-F`）組成
   （那是 hash）。沒有檢查碼。

Solana 與 XRP 的 `normalized` 是原文（區分大小寫）。

## wallet.find_all（1b 補充） 的 1b 規則

候選字串的切法不變。另外，判定為 **Solana** 的候選如果看得出是 Base64 的一段就不算：前一個字元是 `+`，或後一個字元是
`+`、`/`、`=`（前一個字元是 `/` 不算，因為區塊瀏覽器的網址是 `/address/<地址>`）。

## wallet.swap（1b 補充）

狀態機不變；只是 `wallet.find_all` 多認得 Solana、XRP，而 EIP-55 錯誤的 ETH 字串不再是地址。
