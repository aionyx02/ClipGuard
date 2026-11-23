// ClipGuard content script（isolated world）。
//
// 1. paste：可編輯欄位貼上前檢查剪貼簿文字，有機密才攔下並詢問；沒有機密完全不碰事件。
// 2. copy／cut：比對使用者選取的文字與網頁實際寫進剪貼簿的內容（main-world.js 回報），不一致就警告。
//
// 偵測邏輯在 lib/*.js（ES module），這裡是 classic script，所以用動態 import 載入。
// 載入完成前發生的貼上一律放行（fail open），寧可漏抓也不要弄壞網站。
(() => {
  'use strict';
  if (globalThis.__clipguardContentLoaded) return;
  globalThis.__clipguardContentLoaded = true;

  const WRITE_EVENT = 'clipguard:page-clipboard-write';
  // 使用者複製後多久內網頁又呼叫 writeText，算是「改寫這次複製」。
  const LATE_WRITE_MS = 2000;

  let lib = null;
  let packs = null;
  Promise.all([
    import(chrome.runtime.getURL('lib/secrets.js')),
    import(chrome.runtime.getURL('lib/pastejack.js')),
  ]).then(([secrets, pastejack]) => {
    lib = { ...secrets, ...pastejack };
    // 個資的國家包依瀏覽器偏好語言選（#27，例如 zh-TW 開台灣包、en-US 開美國包）；通用包一律開。
    packs = secrets.packsForLocales(navigator.languages && navigator.languages.length ? navigator.languages : [navigator.language]);
  }, () => {});

  // ====================================================================
  // 貼上
  // ====================================================================

  // 我們自己重新派送的 paste 事件，不要再攔一次。
  const ownEvents = new WeakSet();
  const TEXT_INPUT_TYPES = new Set(['text', 'search', 'url', 'tel', 'email', '']);

  function editableTarget(event) {
    const el = event.composedPath()[0];
    if (!(el instanceof Element)) return null;
    if (el instanceof HTMLTextAreaElement) return el.readOnly || el.disabled ? null : el;
    if (el instanceof HTMLInputElement) {
      // 密碼欄位本來就是拿來貼密碼／金鑰的，不打擾。
      return TEXT_INPUT_TYPES.has(el.type) && !el.readOnly && !el.disabled ? el : null;
    }
    if (el.isContentEditable || el.ownerDocument.designMode === 'on') return el;
    return null;
  }

  function isTextControl(el) {
    return el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement;
  }

  function saveCaret(el) {
    if (isTextControl(el)) return { start: el.selectionStart, end: el.selectionEnd };
    const sel = el.ownerDocument.getSelection();
    return { range: sel && sel.rangeCount ? sel.getRangeAt(0).cloneRange() : null };
  }

  function restoreCaret(el, caret) {
    el.focus({ preventScroll: true });
    if (isTextControl(el)) {
      if (caret.start != null) el.setSelectionRange(caret.start, caret.end);
    } else if (caret.range) {
      const sel = el.ownerDocument.getSelection();
      sel.removeAllRanges();
      sel.addRange(caret.range);
    }
  }

  function snapshotClipboard(dt) {
    const data = [];
    for (const type of dt.types) {
      if (type === 'Files') continue;
      try {
        data.push([type, dt.getData(type)]);
      } catch {
        // 某些格式讀不到就略過。
      }
    }
    return data;
  }

  /**
   * 把選定的內容貼進原本的欄位。先派送一個合成的 paste 事件，讓 Google Docs、Notion 這類
   * 自己處理貼上的編輯器照常運作；網頁沒處理（沒 preventDefault）才由我們插入文字。
   */
  function insert(el, caret, data) {
    restoreCaret(el, caret);
    const text = (data.find(([t]) => t === 'text/plain') || [, ''])[1];
    let handledByPage = false;
    try {
      const dt = new DataTransfer();
      for (const [type, value] of data) dt.setData(type, value);
      const ev = new ClipboardEvent('paste', { clipboardData: dt, bubbles: true, cancelable: true, composed: true });
      ownEvents.add(ev);
      handledByPage = !el.dispatchEvent(ev);
    } catch {
      handledByPage = false;
    }
    if (handledByPage) return;
    // execCommand('insertText') 會觸發原生 input 事件、可以復原，React 等框架也收得到。
    if (el.ownerDocument.execCommand('insertText', false, text)) return;
    fallbackInsert(el, caret, text);
  }

  function fallbackInsert(el, caret, text) {
    if (isTextControl(el)) {
      el.setRangeText(text, el.selectionStart, el.selectionEnd, 'end');
    } else {
      const sel = el.ownerDocument.getSelection();
      if (!sel || !sel.rangeCount) return;
      const range = sel.getRangeAt(0);
      range.deleteContents();
      const node = el.ownerDocument.createTextNode(text);
      range.insertNode(node);
      range.setStartAfter(node);
      range.collapse(true);
      sel.removeAllRanges();
      sel.addRange(range);
    }
    el.dispatchEvent(new InputEvent('input', { bubbles: true, inputType: 'insertFromPaste', data: text }));
  }

  function onPaste(event) {
    if (!lib || ownEvents.has(event) || !event.isTrusted || !event.clipboardData) return;
    const el = editableTarget(event);
    if (!el) return;
    const text = event.clipboardData.getData('text/plain');
    if (!text) return;
    const findings = lib.findSecrets(text, { packs });
    if (findings.length === 0) return; // 沒有機密：不 preventDefault，網站行為完全不變。

    // 有機密：攔下原本的貼上，連網頁自己的 paste handler 也不讓它看到原文。
    event.preventDefault();
    event.stopImmediatePropagation();

    const caret = saveCaret(el);
    const original = snapshotClipboard(event.clipboardData);
    const masked = lib.maskText(text, findings);

    showPastePrompt(el, findings, masked, (choice) => {
      if (choice === 'masked') insert(el, caret, [['text/plain', masked]]);
      else if (choice === 'original') insert(el, caret, original);
      else restoreCaret(el, caret);
    });
  }

  window.addEventListener('paste', onPaste, true);

  // ====================================================================
  // 複製（pastejacking）
  // ====================================================================

  let pendingCopy = null;
  let lastCopy = null;

  function selectedText() {
    // input／textarea 裡的選取不一定反映在 getSelection()，另外處理。
    let active = document.activeElement;
    while (active && active.shadowRoot && active.shadowRoot.activeElement) active = active.shadowRoot.activeElement;
    if (isTextControl(active) && active.selectionStart !== active.selectionEnd) {
      try {
        return active.value.slice(active.selectionStart, active.selectionEnd);
      } catch {
        // type=email 等欄位不支援 selectionStart。
      }
    }
    const sel = window.getSelection();
    return sel ? sel.toString() : '';
  }

  function onCopyCapture(event) {
    const pending = { event, selection: selectedText(), setData: null, bubbleData: null, asyncWrite: null };
    pendingCopy = pending;
    // 事件派送是同步的；排到下一個 task 時所有 listener 都跑完了，再看網頁做了什麼。
    setTimeout(() => finishCopy(pending), 0);
  }

  function onCopyBubble(event) {
    // 網頁沒有 stopPropagation 的話，在這裡可以直接讀到實際寫入的內容，不必依賴 main world 的回報。
    if (pendingCopy && pendingCopy.event === event && event.defaultPrevented && event.clipboardData) {
      try {
        pendingCopy.bubbleData = event.clipboardData.getData('text/plain');
      } catch {
        // 忽略
      }
    }
  }

  function finishCopy(p) {
    if (pendingCopy === p) pendingCopy = null;
    lastCopy = { selection: p.selection, time: Date.now() };
    let written = null;
    // 沒有 preventDefault 時瀏覽器會照原生方式複製選取文字，setData 的內容不會生效。
    if (p.event.defaultPrevented) written = p.bubbleData ?? p.setData ?? '';
    if (p.asyncWrite != null) written = p.asyncWrite; // writeText 會在事件結束後覆蓋剪貼簿
    if (written == null) return;
    evaluate(p.selection, written);
  }

  function onPageClipboardWrite(event) {
    if (!lib || typeof event.detail !== 'string') return;
    let msg;
    try {
      msg = JSON.parse(event.detail);
    } catch {
      return;
    }
    if (!msg || typeof msg.text !== 'string') return;
    if (msg.api === 'setData') {
      // copy 事件以外的 setData（例如拖放）跟剪貼簿無關。
      if (pendingCopy) pendingCopy.setData = msg.text;
      return;
    }
    if (pendingCopy) {
      pendingCopy.asyncWrite = msg.text;
      return;
    }
    // 複製後不久、而且使用者這段時間沒有再點擊或按鍵，網頁卻寫入剪貼簿 → 視為偷改這次複製。
    // 使用者之後又點了網頁上的「複製」按鈕，就是新的寫入，跟之前選取的文字無關。
    const overwritesCopy = lastCopy && Date.now() - lastCopy.time < LATE_WRITE_MS && lastInputTime <= lastCopy.time;
    evaluate(overwritesCopy ? lastCopy.selection : '', msg.text);
  }

  let lastInputTime = 0;
  const markInput = (e) => {
    // Ctrl+C 本身的按鍵（keydown 在 copy 事件之前）不算新的操作。
    if (e.type === 'keydown' && (e.ctrlKey || e.metaKey) && /^[cx]$/i.test(e.key)) return;
    if (e.isTrusted) lastInputTime = Date.now();
  };
  window.addEventListener('pointerdown', markInput, true);
  window.addEventListener('keydown', markInput, true);

  function evaluate(selection, written) {
    if (!lib) return;
    const result = lib.analyzeCopy({ selection, written });
    if (result.warn) showCopyWarning(selection, written, result);
  }

  for (const type of ['copy', 'cut']) {
    window.addEventListener(type, onCopyCapture, true);
    window.addEventListener(type, onCopyBubble, false);
  }
  document.addEventListener(WRITE_EVENT, onPageClipboardWrite, true);

  // ====================================================================
  // UI（closed shadow DOM，網站 CSS 影響不到，網站 JS 也讀不到內容）
  // ====================================================================

  const STYLE = `
    :host { all: initial; }
    .box {
      --bg: #ffffff; --fg: #1f2328; --muted: #59636e; --border: #d1d9e0;
      --accent: #0969da; --accent-fg: #ffffff; --warn: #9a6700; --danger: #cf222e;
      position: fixed; z-index: 2147483647; box-sizing: border-box;
      width: min(360px, calc(100vw - 32px)); padding: 12px 14px;
      background: var(--bg); color: var(--fg); border: 1px solid var(--border); border-radius: 8px;
      box-shadow: 0 8px 24px rgba(0,0,0,.18);
      font: 13px/1.5 system-ui, "Microsoft JhengHei", "PingFang TC", sans-serif;
    }
    @media (prefers-color-scheme: dark) {
      .box { --bg: #1f2328; --fg: #f0f6fc; --muted: #9198a1; --border: #3d444d;
             --accent: #4493f8; --accent-fg: #ffffff; --warn: #d29922; --danger: #f85149; }
    }
    .title { font-weight: 600; margin: 0 0 6px; }
    .title.warn { color: var(--warn); }
    .title.danger { color: var(--danger); }
    ul { margin: 0 0 8px; padding-left: 18px; }
    li { margin: 2px 0; }
    code, .preview {
      font-family: ui-monospace, Consolas, monospace; font-size: 12px; word-break: break-all;
    }
    .preview {
      display: block; max-height: 72px; overflow: auto; margin: 0 0 10px; padding: 6px 8px;
      background: color-mix(in srgb, var(--fg) 6%, transparent); border-radius: 4px; white-space: pre-wrap;
    }
    .label { color: var(--muted); font-size: 12px; margin: 0 0 2px; }
    .buttons { display: flex; flex-wrap: wrap; gap: 6px; justify-content: flex-end; }
    button {
      font: inherit; cursor: pointer; padding: 4px 10px; border-radius: 6px;
      border: 1px solid var(--border); background: transparent; color: var(--fg);
    }
    button.primary { background: var(--accent); border-color: var(--accent); color: var(--accent-fg); }
    button:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
    .status { color: var(--muted); font-size: 12px; margin: 6px 0 0; }
  `;

  let currentUi = null;

  function closeUi() {
    const ui = currentUi;
    if (!ui) return;
    currentUi = null;
    ui.host.remove();
    if (ui.onClose) ui.onClose();
  }

  function el(tag, props = {}, ...children) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(props)) {
      if (k === 'class') node.className = v;
      else if (k.startsWith('on')) node.addEventListener(k.slice(2), v);
      else node.setAttribute(k, v);
    }
    for (const c of children) node.append(c); // append 字串會當純文字，不會解析 HTML
    return node;
  }

  function mountUi(box, onClose) {
    closeUi();
    const host = document.createElement('clipguard-ui');
    const root = host.attachShadow({ mode: 'closed' });
    root.append(el('style', {}, STYLE), box);
    (document.body || document.documentElement).append(host);
    currentUi = { host, onClose };
    return host;
  }

  // 提示框裡的按鍵（特別是 Enter）完全不讓網頁看到：有些聊天網站在 window／document 上聽 Enter 當「送出」，
  // 連 capture 階段都要擋。content script 在 document_start 就註冊，通常比網頁自己的 listener 早。
  // 只擋傳遞、不擋預設動作，所以 Enter／空白鍵照常會按下焦點所在的按鈕，Tab 也照常移動焦點。
  // 在提示框按下 Enter 選擇後，焦點已經回到輸入框，放開 Enter 的 keyup 會落在輸入框上，也一併擋掉。
  let swallowEnterKeyup = false;
  function onUiKey(event) {
    if (event.type === 'keyup' && event.key === 'Enter' && swallowEnterKeyup) {
      swallowEnterKeyup = false;
      event.stopImmediatePropagation();
      return;
    }
    const ui = currentUi;
    if (!ui || !event.composedPath().includes(ui.host)) return;
    event.stopImmediatePropagation();
    if (event.type === 'keydown' && event.key === 'Enter') swallowEnterKeyup = true;
    if (event.type === 'keydown' && event.key === 'Escape') closeUi();
  }
  for (const type of ['keydown', 'keypress', 'keyup']) window.addEventListener(type, onUiKey, true);

  function placeNear(box, target) {
    const r = target.getBoundingClientRect();
    const width = box.offsetWidth;
    const height = box.offsetHeight;
    const vw = document.documentElement.clientWidth;
    const vh = document.documentElement.clientHeight;
    let top = r.bottom + 6;
    if (top + height > vh - 8) top = Math.max(8, r.top - height - 6);
    const left = Math.min(Math.max(8, r.left), Math.max(8, vw - width - 8));
    box.style.top = `${Math.min(top, Math.max(8, vh - height - 8))}px`;
    box.style.left = `${left}px`;
  }

  function showPastePrompt(target, findings, masked, decide) {
    let decided = false;
    const choose = (choice) => {
      if (decided) return;
      decided = true;
      closeUi();
      decide(choice);
    };
    const counts = new Map();
    for (const f of findings) counts.set(f.label, (counts.get(f.label) || 0) + 1);
    const items = [...counts].map(([label, n]) => el('li', {}, n > 1 ? `${label} × ${n}` : label));

    const primary = el('button', { class: 'primary', type: 'button', onclick: () => choose('masked') }, '貼上遮罩版本');
    const box = el('div', { class: 'box', role: 'dialog', 'aria-label': 'ClipGuard 機密貼上提醒' },
      el('p', { class: 'title warn' }, 'ClipGuard：要貼上的內容含有機密'),
      el('ul', {}, ...items),
      el('p', { class: 'label' }, '遮罩後會貼上：'),
      el('span', { class: 'preview' }, masked.length > 200 ? `${masked.slice(0, 200)}…` : masked),
      el('div', { class: 'buttons' },
        el('button', { type: 'button', onclick: () => choose('cancel') }, '取消'),
        el('button', { type: 'button', onclick: () => choose('original') }, '貼上原文'),
        primary,
      ),
    );
    // 關閉方式（Esc、另一個提示取代）都算取消。
    mountUi(box, () => choose('cancel'));
    placeNear(box, target);
    primary.focus({ preventScroll: true });
  }

  function showCopyWarning(selection, written, result) {
    const status = el('p', { class: 'status' });
    const writeClipboard = (text, done) => {
      navigator.clipboard.writeText(text).then(
        () => { status.textContent = done; },
        () => { status.textContent = '無法寫入剪貼簿，請重新複製一次。'; },
      );
    };
    const buttons = [el('button', { type: 'button', onclick: closeUi }, '關閉')];
    buttons.unshift(el('button', { type: 'button', onclick: () => writeClipboard('', '已清空剪貼簿。') }, '清空剪貼簿'));
    if (selection) {
      buttons.push(el('button', { class: 'primary', type: 'button', onclick: () => writeClipboard(selection, '已改回你選取的文字。') }, '改回我選取的文字'));
    }
    const title = selection ? 'ClipGuard：這個網頁改寫了你複製的內容' : 'ClipGuard：這個網頁把可疑內容寫進剪貼簿';
    const box = el('div', { class: 'box', role: 'alertdialog', 'aria-label': 'ClipGuard 剪貼簿警告' },
      el('p', { class: 'title danger' }, title),
      el('ul', {}, ...result.reasons.map((r) => el('li', {}, r))),
      el('p', { class: 'label' }, '實際寫入剪貼簿：'),
      el('span', { class: 'preview' }, lib.preview(written, 300)),
      el('p', { class: 'label' }, '先不要貼到終端機、Win+R 或檔案總管網址列。'),
      el('div', { class: 'buttons' }, ...buttons),
      status,
    );
    mountUi(box);
    box.style.top = '16px';
    box.style.right = '16px';
  }
})();
