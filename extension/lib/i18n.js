// 介面文字（#27）：用 Chrome 的 i18n（_locales/<語系>/messages.json，預設 en）。
// 在 Chrome 裡直接用 chrome.i18n.getMessage；node 測試沒有 chrome，改用 setMessages() 塞進來的 messages.json，
// 替換規則照 Chrome：$NAME$ 換成 placeholders 的 content，content 裡的 $1…$9 換成參數，$$ 是 $。

let fallback = null;

/** 測試用：指定一份 messages.json 的內容（null 表示清掉）。 */
export function setMessages(messages) {
  fallback = messages;
}

function format(entry, subs) {
  if (!entry) return '';
  const placeholders = Object.fromEntries(
    Object.entries(entry.placeholders || {}).map(([k, v]) => [k.toLowerCase(), v.content]),
  );
  return entry.message
    .replace(/\$([a-z0-9_@]+)\$/gi, (m, name) => placeholders[name.toLowerCase()] ?? m)
    .replace(/\$(\$|[1-9])/g, (m, d) => (d === '$' ? '$' : String(subs[Number(d) - 1] ?? '')));
}

/** 取一則訊息；沒有這則訊息時回傳空字串（同 chrome.i18n.getMessage）。 */
export function t(key, ...subs) {
  const i18n = globalThis.chrome?.i18n;
  if (i18n?.getMessage) return i18n.getMessage(key, subs.map(String));
  return format(fallback?.[key], subs);
}

const messageName = (s) => String(s).replace(/[^A-Za-z0-9_]/g, '_');

/**
 * 機密在提示框裡顯示的名稱：規則檔的規則看 rule_<id>，個資看 label_<type>；沒有翻譯就用偵測器給的 label。
 * @param {{type: string, label: string, rule?: string}} finding
 */
export function displayLabel(finding) {
  const key = finding.rule ? `rule_${messageName(finding.rule)}` : `label_${messageName(finding.type)}`;
  return t(key) || finding.label;
}
