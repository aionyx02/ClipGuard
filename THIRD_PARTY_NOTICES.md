# 第三方授權聲明

PasteWarden 內含以下第三方專案的內容。

## gitleaks

- 專案：https://github.com/gitleaks/gitleaks
- 使用的部分：預設規則 `config/gitleaks.toml`（v8.30.1，commit 5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c），轉換成 `rules/gitleaks.json` 和 `rules/gitleaks-late.json`（舊版用 `tools/convert-gitleaks.mjs`，Phase 1 起改由 `cargo xtask rules gitleaks` 負責）。轉換時改寫了 regex 語法、拿掉部分規則與 allowlist 範例，細節見 `docs/spec/detection-rules.md` §5.4。
- 授權：MIT License

```
MIT License

Copyright (c) 2019 Zachary Rice

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## BIP-39 英文單字表

- 專案：https://github.com/bitcoin/bips
- 使用的部分：`bip-0039/english.txt`（2048 個字，未修改），存成 `rules/secret/bip39-english.txt`，用來偵測錢包助記詞（`docs/spec/detection-rules.md` §5.7）。
- 來源：https://github.com/bitcoin/bips/blob/0d99ffd39fdaf75209c43b1f8ec3fbbc23f10814/bip-0039/english.txt（取用時的 master，commit `0d99ffd39fdaf75209c43b1f8ec3fbbc23f10814`；這個檔案最後一次修改是 commit `ce1862ac6bcffa1dd20aad858380e51e66e949ea`）。SHA-256：`2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`
- 授權：MIT License。BIP-39（作者 Marek Palatinus、Pavol Rusnak、Aaron Voisine、Sean Bowe）的 Copyright 段寫著「This BIP falls under the MIT License.」

```
MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
