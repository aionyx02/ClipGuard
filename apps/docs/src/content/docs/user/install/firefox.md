---
title: Firefox
description: 在 Firefox 安裝 PasteWarden（xpi）。
sidebar:
  order: 2
---

Firefox 版以 `.xpi` 檔發布在 [GitHub Releases](https://github.com/aionyx02/paste-warden/releases)。

:::caution[簽章前的版本]
Mozilla 簽章（AMO unlisted）會在 Phase 6 加入。在那之前的 xpi **沒有簽章**，一般版 Firefox 只能「暫時載入」，重新啟動瀏覽器後就會移除。
:::

## 已簽章的版本（Phase 6 起）

1. 在 Firefox 中打開 Releases 頁面，點 `paste-warden-firefox.xpi`。
2. Firefox 會詢問是否安裝，按 **新增**。
3. 在工具列的擴充功能選單把 PasteWarden 釘選出來。

## 未簽章的測試版

1. 下載 `paste-warden-firefox.xpi`。
2. 在網址列輸入 `about:debugging#/runtime/this-firefox`。
3. 按 **載入暫時性附加元件…**，選擇下載的 xpi。

暫時載入的附加元件在 Firefox 重新啟動後會消失，需要再載入一次。Firefox Developer Edition 與 Nightly 可以在 `about:config` 把 `xpinstall.signatures.required` 設成 `false` 後永久安裝未簽章版本；一般版 Firefox 不支援這個設定。

## 權限

Firefox 可能把「存取所有網站的資料」列為選用權限。PasteWarden 需要它才能在網頁寫入剪貼簿時攔截，請在附加元件管理員的「權限」分頁開啟。原因見[隱私承諾](../../privacy/#擴充功能的權限)。
