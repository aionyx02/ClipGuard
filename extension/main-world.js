// 跑在網頁的 MAIN world（與網頁自己的 JS 同一個環境），document_start 注入，比網頁腳本先執行。
//
// 為什麼需要它：content script 在 isolated world，網頁呼叫 DataTransfer.setData 或
// navigator.clipboard.writeText 時，isolated world 看不到這些呼叫，也看不到傳了什麼值。
// 這裡包裝這些 API，把「網頁寫進剪貼簿的文字」用 CustomEvent 告訴 content.js。
//
// 這個檔案只轉送，不判斷、不存、不連網；包裝後的函式行為與原本完全相同。
(() => {
  'use strict';
  const EVENT = 'clipguard:page-clipboard-write';
  const MAX = 100_000;
  const dispatch = EventTarget.prototype.dispatchEvent;

  function report(api, text) {
    try {
      // detail 只放字串：物件跨 world 傳遞時 isolated world 讀不到。
      const detail = JSON.stringify({ api, text: String(text).slice(0, MAX) });
      dispatch.call(document, new CustomEvent(EVENT, { detail }));
    } catch {
      // 回報失敗不能影響網頁本身的複製功能。
    }
  }

  // 讓包裝後的函式在 toString、name、length 上看起來跟原生一樣，減少網站相容性問題。
  function wrap(proto, name, makeWrapper) {
    const original = proto && proto[name];
    if (typeof original !== 'function') return;
    const wrapped = makeWrapper(original);
    Object.defineProperty(wrapped, 'name', { value: original.name });
    Object.defineProperty(wrapped, 'length', { value: original.length });
    const toString = Function.prototype.toString;
    Object.defineProperty(wrapped, 'toString', { value: function () { return toString.call(original); } });
    Object.defineProperty(proto, name, { ...Object.getOwnPropertyDescriptor(proto, name), value: wrapped });
  }

  // copy 事件中的 event.clipboardData.setData('text/plain', ...)
  wrap(globalThis.DataTransfer && DataTransfer.prototype, 'setData', (original) => function (format, data) {
    const result = original.apply(this, arguments);
    if (typeof format === 'string' && /^\s*text(\/plain)?\s*$/i.test(format)) report('setData', data);
    return result;
  });

  // navigator.clipboard.writeText(text)
  wrap(globalThis.Clipboard && Clipboard.prototype, 'writeText', (original) => function (text) {
    const result = original.apply(this, arguments);
    report('writeText', text);
    return result;
  });

  // navigator.clipboard.write([new ClipboardItem({'text/plain': blob})])：取出純文字部分。
  wrap(globalThis.Clipboard && Clipboard.prototype, 'write', (original) => function (items) {
    const result = original.apply(this, arguments);
    try {
      for (const item of items || []) {
        if (item && Array.isArray(item.types) && item.types.includes('text/plain')) {
          item.getType('text/plain').then((blob) => blob.text()).then((t) => report('write', t), () => {});
          break;
        }
      }
    } catch {
      // 忽略：格式不合的參數交給原生 API 自己報錯。
    }
    return result;
  });
})();
