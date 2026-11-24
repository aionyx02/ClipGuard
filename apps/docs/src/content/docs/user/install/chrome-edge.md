---
title: Chrome / Edge
description: 在 Chrome 或 Edge 載入 PasteWarden 擴充功能（未封裝）。
sidebar:
  order: 1
---

PasteWarden 不在 Chrome 線上應用程式商店上架，改從 GitHub Releases 下載後自己載入。這樣每個版本都能對照原始碼和建置紀錄。

:::caution[開發中]
擴充功能在 Phase 3 開發中，第一個正式版本發布前，Releases 頁面上可能還沒有檔案。
:::

## 步驟

1. 到 [GitHub Releases](https://github.com/aionyx02/paste-warden/releases) 下載最新版的 `paste-warden-chrome.zip`。
2. 把 zip **解壓縮**到一個你不會刪掉的資料夾，例如「文件\PasteWarden」。之後瀏覽器會一直從這個資料夾讀取擴充功能。
3. 在網址列輸入 `chrome://extensions`（Edge 是 `edge://extensions`）。
4. 打開右上角（Edge 在左下角）的 **開發人員模式**。
5. 按 **載入未封裝項目**，選剛剛解壓縮出來、裡面有 `manifest.json` 的資料夾。
6. 列表中出現 PasteWarden 就完成了。建議按拼圖圖示，把它釘選在工具列上。

## 更新

下載新版 zip，解壓縮後覆蓋同一個資料夾，再到擴充功能頁按 PasteWarden 卡片上的重新載入按鈕。

## 常見問題

**瀏覽器每次啟動都提醒「停用開發人員模式擴充功能」？** 這是 Chrome 對所有自行載入的擴充功能的提醒，選「保留」即可。

**需要哪些權限？** 見[隱私承諾](../../privacy/#擴充功能的權限)。
