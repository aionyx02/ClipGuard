// 測試用：node 沒有 chrome.i18n，把 _locales/<語系>/messages.json 塞給 lib/i18n.js。
// 放在 test/ 底下會被 node --test 當成測試檔跑一次，裡面沒有測試，不影響結果。
import { readFileSync } from 'node:fs';
import { setMessages } from '../lib/i18n.js';

export function readMessages(locale) {
  return JSON.parse(readFileSync(new URL(`../_locales/${locale}/messages.json`, import.meta.url), 'utf8'));
}

/** 改用指定語系的訊息（en、zh_TW）。 */
export function useLocale(locale) {
  setMessages(readMessages(locale));
}
