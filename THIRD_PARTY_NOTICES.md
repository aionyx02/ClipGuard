# 第三方授權聲明

PasteWarden 內含以下第三方專案的內容。

## gitleaks

- 專案：https://github.com/gitleaks/gitleaks
- 使用的部分：預設規則 `config/gitleaks.toml`（v8.30.1，commit 5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c），轉換成 `rules/gitleaks.json`（舊版用 `tools/convert-gitleaks.mjs`，Phase 1 起改由 `cargo xtask rules gitleaks` 負責）。轉換時改寫了 regex 語法、拿掉部分規則與 allowlist 範例，細節見 `docs/spec/detection-rules.md` §5.4。
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
