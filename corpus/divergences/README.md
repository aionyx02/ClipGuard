# divergences

刻意和舊版預期不同的語料案例，一個 area 一個檔案（`command.toml`、`secret.toml`…）：

```toml
[[divergence]]
id = "secret.card.017"   # 語料案例 id
kind = "unicode-count"   # bugfix | intentional | legacy-js | unicode-count
reason = "舊版用 UTF-16 計算長度，Rust 用 char（phase-1.md §1.8）"
issue = "#NN"            # 選填
```

案例還是會執行；列在這裡的案例失敗不算整體失敗。已經通過的案例如果還留在這裡，`xtask corpus run` 會要求移除。
