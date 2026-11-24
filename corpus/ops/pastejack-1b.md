# pastejack（1b）

1b 沒有新增 op 或 expect 欄位：`corpus/cases/pastejack-1b-*.jsonl` 用的是既有的 `pastejack.compare`、
`pastejack.normalize`、`pastejack.command_signals`（`ops/pastejack.md`）。下面是 1b 的規則補充，以這裡為準。

## 看不見的字元（擴充）

清單搬到 `rules/pastejack/hidden-chars.json`，並加入桌面版 1b 新增的 **U+034F**（CGJ）、**U+17B4–17B5**（高棉文固有母音）。
插件仍然沒有例外規則，只比數量：使用者自己選到的會互相抵銷。影響 `pastejack.compare`（第 1、3 步）、
`pastejack.normalize`（會刪掉這些字元）和 `pastejack.preview`（顯示成 `⟦U+XXXX⟧`）。

## 指令訊號

樣式搬到 `rules/pastejack/signals.json`（`invocation` 程式名稱清單，或 `regex` 加上 `{b}`、`{WS}`、`{NWS}` 佔位符），
行為不變。訊號 id 固定（對應 `pastejack-sig-<id>` 訊息），順序就是理由的順序。
