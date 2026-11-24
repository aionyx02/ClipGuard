// Pastejacking 判斷：使用者選取的文字 vs. 網頁實際寫進剪貼簿的文字。純函式，可單元測試。
// 說明文字用 _locales 的訊息（#27），名稱見 COMMAND_SIGNALS 和下面的 t(…)。
import { t } from './i18n.js';

// 看不見的字元：零寬、Bidi、soft hyphen、蒙古文分隔符、韓文填充字元、Unicode TAG（U+E0000–E007F，
// 可藏給 AI 的指令）、補充區變體選擇符。這裡比較的是「網頁寫入」比「使用者選取」多出來的數量，
// 使用者自己選到的區旗 emoji、異體字兩邊都有，不會誤判，所以不需要桌面版的例外規則（見 docs §7）。
const HIDDEN_CHARS = /[\u00AD\u115F\u1160\u180E\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\u3164\uFEFF\uFFA0\u{E0000}-\u{E007F}\u{E0100}-\u{E01EF}]/gu;

// 桌面版 CommandDetector「執行訊號」的精簡子集，只用來判斷網頁偷塞的內容像不像要你去執行的指令。
// 完整規則日後應與 C# 端共用（見 extension/README.md）。
const COMMAND_SIGNALS = [
  // 程式名稱後面要接參數、引號、註解或結尾，才像在下指令（同 C# 的 Invocation()）。
  [/(?:^|[\s;&|("'])(?:powershell|pwsh)(?:\.exe)?(?=\s+[-/"'#a-z0-9]|\s*$|\s*[|;&])/im, 'pj_sig_powershell'],
  [/(?:^|[\s;&|("'])mshta(?:\.exe)?(?=\s+[-/"'#a-z0-9]|\s*$|\s*[|;&])/im, 'pj_sig_mshta'],
  [/\bcmd(?:\.exe)?\s+\/[ck]\b/i, 'pj_sig_cmd'],
  [/\b(?:curl|wget)\b[^|\n]*\|\s*(?:ba|z)?sh\b/i, 'pj_sig_pipe_shell'],
  [/\b(?:iex|invoke-expression)\b/i, 'pj_sig_iex'],
  [/\b(?:certutil|bitsadmin|rundll32|regsvr32|msiexec)(?:\.exe)?\b/i, 'pj_sig_lolbin'],
  [/\bsudo\s+\S/i, 'pj_sig_sudo'],
];

/** 回傳文字中命中的指令訊號說明（目前語系）。 */
export function commandSignals(text) {
  if (typeof text !== 'string' || !text) return [];
  return COMMAND_SIGNALS.filter(([re]) => re.test(text)).map(([, key]) => t(key));
}

/** 比較用的正規化：統一換行、不換行空白，壓縮連續空白，去頭尾。 */
export function normalize(text) {
  return String(text ?? '')
    .replace(HIDDEN_CHARS, '')
    .replace(/\r\n?/g, '\n')
    .replace(/[   　]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function hiddenCharCount(text) {
  return (String(text ?? '').match(HIDDEN_CHARS) || []).length;
}

/**
 * @param {{selection: string, written: string}} input
 *   selection：copy 當下使用者選取的文字（可能是空字串，例如按網頁上的「複製」按鈕）。
 *   written：網頁實際要寫進剪貼簿的文字。
 * @returns {{verdict: 'empty'|'same'|'appended'|'replaced'|'unselected', warn: boolean, reasons: string[]}}
 *   empty：網頁寫入空內容（擋複製）；
 *   same：內容一致；appended：保留原文但多加了東西（新聞網站常加「出處」）；
 *   replaced：原文不見了或被改掉；unselected：沒有選取文字，網頁自行寫入。
 */
export function analyzeCopy({ selection, written }) {
  const sel = normalize(selection);
  const wr = normalize(written);
  const reasons = [];

  // 網頁擋下複製（寫入空字串）不是 pastejacking，只是不讓你複製。
  if (!wr && hiddenCharCount(written) === 0) return { verdict: 'empty', warn: false, reasons };

  const newHidden = hiddenCharCount(written) > hiddenCharCount(selection);
  if (newHidden) reasons.push(t('pj_hidden'));

  // 指令訊號只算「網頁額外加進來的」，使用者自己選取的指令（教學文件）不算。
  const selSignals = new Set(commandSignals(selection));
  const addedSignals = commandSignals(written).filter((r) => !selSignals.has(r));
  // 多行內容的換行等於按 Enter，貼進終端機會直接執行。
  const addedNewlineExec = /\n/.test(String(written ?? '').trim()) && !/\n/.test(String(selection ?? '').trim()) && addedSignals.length > 0;
  reasons.push(...addedSignals.map((r) => t('pj_added', r)));
  if (addedNewlineExec) reasons.push(t('pj_newline'));

  if (!sel) {
    return { verdict: 'unselected', warn: addedSignals.length > 0 || newHidden, reasons };
  }
  if (sel === wr) {
    return { verdict: 'same', warn: newHidden, reasons };
  }
  if (wr.includes(sel)) {
    // 附加「本文出處」之類的文字很常見，不值得打擾；只有附加內容可疑才警告。
    return { verdict: 'appended', warn: reasons.length > 0, reasons };
  }
  reasons.unshift(t('pj_replaced'));
  return { verdict: 'replaced', warn: true, reasons };
}

/** 給 UI 顯示用：截斷，並把看不見的字元換成可見標記。 */
export function preview(text, max = 160) {
  const visible = String(text ?? '').replace(HIDDEN_CHARS, (c) => `⟦U+${c.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}⟧`);
  return visible.length > max ? `${visible.slice(0, max)}…` : visible;
}
