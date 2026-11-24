---
title: Userscript
description: 用 Violentmonkey 或 Tampermonkey 安裝 PasteWarden userscript。
sidebar:
  order: 3
---

不想裝擴充功能，或用的瀏覽器不支援（例如 iOS Safari 搭配 Userscripts App），可以改用 userscript。功能和擴充功能的網頁部分相同：攔截網頁寫入剪貼簿、貼上機密前確認、Pastejacking 偵測。

## 步驟

1. 先安裝 userscript 管理器，建議 [Violentmonkey](https://violentmonkey.github.io/)（開放原始碼），或 Tampermonkey。
2. 到 [GitHub Releases](https://github.com/aionyx02/paste-warden/releases) 點 `paste-warden.user.js`。
3. 管理器會顯示安裝頁面，確認來源後按 **安裝**。

之後管理器會依 `@updateURL` 自動從 GitHub Releases 檢查更新。

## Chrome / Edge 的額外設定

在 Manifest V3 下，Chrome 和 Edge 預設不讓擴充功能執行 userscript。若管理器提示 userscript 沒有執行，到擴充功能頁面打開該管理器卡片「詳細資料」中的 **允許使用者指令碼**（較舊的版本則需要打開開發人員模式）。

## 和擴充功能的差異

- 設定存在管理器裡（`GM_setValue`），不會和擴充功能同步。
- 某些網站的內容安全政策（CSP）很嚴格，userscript 會改用較慢的 JavaScript 版引擎，判定結果相同。
- 兩者不要同時啟用，否則同一個事件會被檢查兩次。
