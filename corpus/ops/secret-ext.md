# secret（瀏覽器插件特有）

## `secret.packs_for_locales`

舊版插件 `packsForLocales(navigator.languages)`：插件沒有設定畫面，所以瀏覽器的**每一個**偏好語言都算，取聯集（`zh-TW`、`en-US` 都列著就開 `tw` 和 `us`）。桌面版只看一個地區設定，見 `secret.packs_for_region`。

- `args`：
  - `locales`：字串陣列（瀏覽器偏好語言的順序）。每個值用 `secret.packs_country_of` 的規則對應國家包，對不到的忽略
- `expect`：
  - `packs`：要開的包（小寫，一定含 `universal`）。**集合**比對：順序不重要，但不能多也不能少
