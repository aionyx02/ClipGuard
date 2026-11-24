<p align="center">
  <img src="assets/banner.svg" alt="PasteWarden" width="100%">
</p>

# PasteWarden 剪貼簿守門員

> 🚧 **重寫中**：PasteWarden（原名 ClipGuard）正在用 Rust 全面重寫，目標支援 Windows、macOS、Linux、Android、瀏覽器擴充功能與 userscript。進度與架構見 [`docs/plan/roadmap.md`](docs/plan/roadmap.md)。舊版 C# 程式在 git 歷史裡（`dev` 分支 Phase 0 之前的 commit）。

PasteWarden 把剪貼簿當成信任邊界，雙向防守：

- **進來的威脅**：假人機驗證騙你按 Win+R 貼上指令（ClickFix / FileFix）、網頁偷換你複製的內容（Pastejacking）、看不見的字元、錢包地址被掉包，以及 AI agent 被網頁騙去執行指令。
- **出去的威脅**：身分證、統編、信用卡、手機、API key、私鑰、助記詞和你自己登記的機密被貼出去。

預設只用本機引擎、零遙測；AI 相關功能（LLM 解說、agent hook、MCP）預設關閉，需要時再自己開啟。

## English

PasteWarden treats the clipboard as a trust boundary. It blocks fake-CAPTCHA "paste this into Win+R" attacks (ClickFix / FileFix), pastejacking, invisible-character tricks and wallet-address swaps, warns before you paste personal data or API keys into a website, and can guard AI coding agents against prompt-injected commands. Everything runs locally; AI features are opt-in. A Rust rewrite targeting Windows, macOS, Linux, Android, browser extensions and userscripts is in progress — see [`docs/plan/roadmap.md`](docs/plan/roadmap.md).

## 文件

| 文件 | 內容 |
|---|---|
| [`docs/plan/roadmap.md`](docs/plan/roadmap.md) | 架構、已定案的決策、各 Phase 範圍 |
| [`docs/spec/detection-rules.md`](docs/spec/detection-rules.md) | 偵測行為規格 |
| [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) | 威脅模型：防什麼、不防什麼 |
| [`corpus/README.md`](corpus/README.md) | 測試語料格式 |

使用說明網站（繁中、English）會在 Phase 3 上線。

## 開發

```sh
cargo test --workspace
cargo run -p xtask -- corpus lint
cargo run -p xtask -- corpus coverage
```

給 AI agent 的開發規則見 [`CLAUDE.md`](CLAUDE.md)。流程：`feature/*` → PR 到 `dev` → PR 到 `main`。

## 授權

[MIT](LICENSE)。`rules/gitleaks.json` 轉換自 [gitleaks](https://github.com/gitleaks/gitleaks) 的預設規則（MIT），見 [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md)。
