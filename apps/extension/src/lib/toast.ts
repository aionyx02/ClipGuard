// Non-blocking notice for `warn` verdicts and pastejacking (the write already went through).
// Closed Shadow DOM, colours from the OS (`prefers-color-scheme`), text via textContent only,
// never takes focus, disappears on its own.

const HOST_TAG = 'paste-warden-notice';
const HOST_STYLE =
  'all:initial!important;position:fixed!important;right:16px!important;bottom:16px!important;z-index:2147483646!important;display:block!important;max-width:min(380px,calc(100vw - 32px))!important;';

const CSS = `
:host{all:initial}
.t{box-sizing:border-box;font:14px/1.45 system-ui,-apple-system,"Segoe UI","Noto Sans TC","PingFang TC","Microsoft JhengHei",sans-serif;
  color:#0f172a;background:#fffbeb;border:1px solid #f59e0b;border-left-width:4px;border-radius:10px;padding:12px 14px;
  box-shadow:0 8px 24px rgba(15,23,42,.18);display:grid;gap:6px}
.b{font-size:12px;font-weight:600;color:#92400e;letter-spacing:.02em}
h2{margin:0;font-size:15px;font-weight:650}
p{margin:0}
ul{margin:0;padding-left:18px}
li{margin:2px 0}
button{justify-self:end;font:inherit;font-size:13px;border:1px solid #d97706;background:transparent;color:inherit;border-radius:6px;padding:3px 10px;cursor:pointer}
button:focus-visible{outline:2px solid #2563eb;outline-offset:2px}
@media (prefers-color-scheme:dark){
  .t{color:#f8fafc;background:#1c1917;border-color:#f59e0b}
  .b{color:#fbbf24}
  button{border-color:#fbbf24}
}
@media (prefers-reduced-motion:no-preference){.t{animation:i .18s ease-out}@keyframes i{from{opacity:0;transform:translateY(8px)}}}
`;

export interface NoticeContent {
  brand: string;
  title: string;
  body: string;
  reasons: string[];
  dismiss: string;
}

let current: { remove: () => void } | null = null;

/** Shows the notice; returns a function that removes it. Replaces any notice already shown. */
export function showNotice(doc: Document, content: NoticeContent, timeoutMs = 10_000): () => void {
  current?.remove();
  const host = doc.createElement(HOST_TAG);
  host.setAttribute('style', HOST_STYLE);
  const root = host.attachShadow({ mode: 'closed' });
  const style = doc.createElement('style');
  style.textContent = CSS;
  const box = doc.createElement('div');
  box.className = 't';
  box.setAttribute('role', 'status');
  box.setAttribute('aria-live', 'polite');
  const brand = doc.createElement('div');
  brand.className = 'b';
  brand.textContent = content.brand;
  const title = doc.createElement('h2');
  title.textContent = content.title;
  const body = doc.createElement('p');
  body.textContent = content.body;
  box.append(brand, title, body);
  if (content.reasons.length > 0) {
    const ul = doc.createElement('ul');
    for (const r of content.reasons.slice(0, 5)) {
      const li = doc.createElement('li');
      li.textContent = r;
      ul.append(li);
    }
    box.append(ul);
  }
  const close = doc.createElement('button');
  close.type = 'button';
  close.textContent = content.dismiss;
  box.append(close);
  root.append(style, box);

  const timer = setTimeout(() => remove(), timeoutMs);
  const remove = () => {
    clearTimeout(timer);
    host.remove();
    if (current === handle) current = null;
  };
  const handle = { remove };
  close.addEventListener('click', remove);
  current = handle;
  (doc.body ?? doc.documentElement).append(host);
  return remove;
}
