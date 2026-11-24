/**
 * PasteWarden's in-page warning layer (phase-3 §3.1/§3.2), used by the extension's content
 * script and the userscript.
 *
 * - Closed Shadow DOM on a custom element under <html>: page CSS/JS can't restyle or read it.
 * - No framework; strings from locales/<lang>/ui-overlay.ftl inlined at build time.
 * - Colours follow the OS (`prefers-color-scheme`), not the page.
 * - A modal <dialog> (top layer when `showModal` exists) with a focus trap.
 * - Everything from the Report is inserted with `textContent`: no HTML from the page or the
 *   clipboard is ever parsed.
 * - The risky choices ("allow once", "paste original") only react to trusted user events and
 *   are armed after a short delay, so a page can't click them for the user and a double-click
 *   that opened the dialog can't land on them.
 */
import type { Locale, Report } from '@paste-warden/ui/report';
import { format, type Strings, stringsFor, systemLocale } from './strings';
import { CSS } from './styles';

export { parseFtl, systemLocale } from './strings';

export type BlockedChoice = 'allow-once' | 'keep-blocked';
export type PasteChoice = 'masked' | 'original' | 'cancel';

export interface OverlayOptions {
  /** Default: the browser's UI language (zh-TW for any Chinese, else English). */
  locale?: Locale;
  /** Override individual `ui-overlay-*` strings (e.g. from `@paste-warden/core`'s `messages()`). */
  strings?: Strings;
  /** Document to attach to. Default: the global `document`. */
  document?: Document;
  /** Ignore synthetic (`isTrusted === false`) events for the risky choices. Default true. */
  trustedEventsOnly?: boolean;
  /** ms before the risky button can be used. Default 600. */
  armDelayMs?: number;
}

export interface BlockedOptions extends OverlayOptions {
  /** The page that tried to write to the clipboard. */
  url: string;
}

const HOST_TAG = 'paste-warden-overlay';
const HOST_STYLE =
  'all:initial!important;position:fixed!important;inset:0!important;z-index:2147483647!important;display:block!important;';

type Child = Node | string | null | undefined | false;

function el<K extends keyof HTMLElementTagNameMap>(
  doc: Document,
  tag: K,
  attrs: Record<string, string> = {},
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const node = doc.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
  for (const c of children) {
    if (c) node.append(c); // strings become text nodes: never parsed as HTML
  }
  return node;
}

const ICON_STOP = 'M8.2 2.5h7.6l5.7 5.7v7.6l-5.7 5.7H8.2l-5.7-5.7V8.2zM9 9l6 6M15 9l-6 6';
const ICON_WARN = 'M12 3.5 2.5 20h19zM12 10v4.5M12 17.5v.01';

function icon(doc: Document, d: string): SVGSVGElement {
  const ns = 'http://www.w3.org/2000/svg';
  const svg = doc.createElementNS(ns, 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('aria-hidden', 'true');
  svg.setAttribute('fill', 'none');
  svg.setAttribute('stroke', 'currentColor');
  svg.setAttribute('stroke-width', '2');
  svg.setAttribute('stroke-linecap', 'round');
  svg.setAttribute('stroke-linejoin', 'round');
  const path = doc.createElementNS(ns, 'path');
  path.setAttribute('d', d);
  svg.append(path);
  return svg;
}

/** Only one overlay at a time; opening a new one settles the old one with its safe choice. */
let active: { close: () => void } | null = null;

interface Frame<T> {
  doc: Document;
  dialog: HTMLDialogElement;
  t: (id: string, args?: Record<string, string | number>) => string;
  settle: (value: T) => void;
  promise: Promise<T>;
  trusted: (event: Event) => boolean;
  arm: (button: HTMLButtonElement) => void;
}

function openFrame<T>(opts: OverlayOptions, safe: T, tone: 'q' | 'w'): Frame<T> {
  active?.close();
  const doc = opts.document ?? document;
  const strings = { ...stringsFor(opts.locale ?? systemLocale()), ...opts.strings };
  const t = (id: string, args?: Record<string, string | number>) => format(strings, id, args);
  const trustedOnly = opts.trustedEventsOnly ?? true;
  const armDelay = opts.armDelayMs ?? 600;
  const previousFocus = doc.activeElement as HTMLElement | null;

  const host = doc.createElement(HOST_TAG);
  host.setAttribute('style', HOST_STYLE);
  const root = host.attachShadow({ mode: 'closed' });
  const style = el(doc, 'style');
  style.textContent = CSS;
  const dialog = el(doc, 'dialog', { class: tone === 'w' ? 'warn' : '', 'aria-modal': 'true' });
  const wrapper = el(doc, 'div', { class: 'r' }, el(doc, 'div', { class: 'bd' }), dialog);
  root.append(style, wrapper);

  let resolve!: (value: T) => void;
  const promise = new Promise<T>((r) => {
    resolve = r;
  });
  const timers: ReturnType<typeof setTimeout>[] = [];
  let done = false;

  const settle = (value: T) => {
    if (done) return;
    done = true;
    for (const id of timers) clearTimeout(id);
    try {
      if (dialog.open && typeof dialog.close === 'function') dialog.close();
    } catch {
      // Not fatal: the host is removed below anyway.
    }
    host.remove();
    if (active === handle) active = null;
    previousFocus?.focus?.({ preventScroll: true });
    resolve(value);
  };
  const handle = { close: () => settle(safe) };
  active = handle;

  const focusables = () =>
    [...dialog.querySelectorAll<HTMLElement>('button:not(:disabled), summary')].filter(
      (n) => !n.closest('details:not([open]) ol'),
    );

  // Keyboard: trap Tab inside, Esc = safe choice. Keys never reach the page.
  dialog.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') {
      event.preventDefault();
      settle(safe);
    } else if (event.key === 'Tab') {
      const list = focusables();
      if (list.length === 0) return;
      const current = root.activeElement;
      const index = list.indexOf(current as HTMLElement);
      const nextIndex = event.shiftKey
        ? index <= 0
          ? list.length - 1
          : index - 1
        : index === list.length - 1
          ? 0
          : index + 1;
      event.preventDefault();
      list[nextIndex]?.focus();
    }
    event.stopPropagation();
  });
  for (const type of ['keyup', 'keypress', 'paste', 'copy', 'cut'] as const) {
    dialog.addEventListener(type, (e) => e.stopPropagation());
  }
  // The native modal's own Esc handling ("cancel") goes through our safe path.
  dialog.addEventListener('cancel', (event) => {
    event.preventDefault();
    settle(safe);
  });

  (doc.documentElement ?? doc.body).append(host);
  try {
    if (typeof dialog.showModal === 'function' && host.isConnected) dialog.showModal();
    else dialog.setAttribute('open', '');
  } catch {
    dialog.setAttribute('open', '');
  }

  return {
    doc,
    dialog,
    t,
    settle,
    promise,
    trusted: (event) => !trustedOnly || event.isTrusted,
    arm: (button) => {
      if (armDelay <= 0) return;
      button.disabled = true;
      timers.push(
        setTimeout(() => {
          button.disabled = false;
        }, armDelay),
      );
    },
  };
}

function header(
  f: Pick<Frame<never>, 'doc' | 't'>,
  titleId: string,
  title: string,
  iconPath: string,
  risk?: number,
) {
  const { doc, t } = f;
  return el(
    doc,
    'div',
    { class: 'hd' },
    el(doc, 'span', { class: 'ic' }, icon(doc, iconPath)),
    el(
      doc,
      'div',
      {},
      el(doc, 'div', { class: 'br' }, el(doc, 'b', {}, t('ui-overlay-brand'))),
      el(doc, 'h2', { id: titleId }, title),
    ),
    risk !== undefined && el(doc, 'span', { class: 'rk' }, t('ui-overlay-risk', { score: risk })),
  );
}

function onionView(f: Pick<Frame<never>, 'doc' | 't'>, report: Report): HTMLElement | null {
  const { doc, t } = f;
  const trace = report.command.trace;
  if (trace.length === 0) return null;
  const list = el(doc, 'ol');
  trace.forEach((step, i) => {
    list.append(
      el(
        doc,
        'li',
        {},
        el(
          doc,
          'div',
          { class: 'lv' },
          `${t('ui-overlay-layer', { n: i + 1 })} · `,
          el(doc, 'code', {}, step.kind),
          ` · ${step.text}`,
        ),
        el(doc, 'pre', {}, step.preview),
      ),
    );
  });
  return el(
    doc,
    'details',
    {},
    el(doc, 'summary', {}, t('ui-overlay-layers', { count: trace.length })),
    list,
  );
}

function displayUrl(url: string): string {
  try {
    const u = new URL(url);
    return `${u.protocol}//${u.host}${u.pathname === '/' ? '' : u.pathname}`;
  } catch {
    return url.slice(0, 200);
  }
}

/**
 * A page wrote a quarantined command to the clipboard; the caller already replaced it with a
 * harmless notice. Resolves `keep-blocked` (default, Enter, Esc) or `allow-once`.
 */
export function showClipboardBlocked(report: Report, opts: BlockedOptions): Promise<BlockedChoice> {
  const f = openFrame<BlockedChoice>(opts, 'keep-blocked', report.action === 'warn' ? 'w' : 'q');
  const { doc, dialog, t } = f;
  dialog.setAttribute('aria-labelledby', 'pw-t');
  dialog.setAttribute('aria-describedby', 'pw-d');

  const keep = el(doc, 'button', { type: 'button', class: 'pri' }, t('ui-overlay-keep-blocked'));
  const allow = el(doc, 'button', { type: 'button', class: 'dan' }, t('ui-overlay-allow-once'));
  keep.addEventListener('click', () => f.settle('keep-blocked'));
  allow.addEventListener('click', (event) => {
    if (f.trusted(event)) f.settle('allow-once');
  });
  f.arm(allow);

  const reasons = report.command.reasons;
  dialog.append(
    header(
      f,
      'pw-t',
      t('ui-overlay-blocked-title'),
      report.action === 'warn' ? ICON_WARN : ICON_STOP,
      report.command.risk_score,
    ),
    el(
      doc,
      'div',
      { class: 'bdy' },
      el(doc, 'p', { id: 'pw-d' }, t('ui-overlay-blocked-body')),
      el(
        doc,
        'div',
        { class: 'src' },
        `${t('ui-overlay-blocked-source')}:`,
        el(doc, 'code', {}, displayUrl(opts.url)),
      ),
      reasons.length > 0 && el(doc, 'h3', {}, t('ui-overlay-reasons')),
      reasons.length > 0 && el(doc, 'ul', {}, ...reasons.map((r) => el(doc, 'li', {}, r.text))),
      onionView(f, report),
    ),
    el(
      doc,
      'div',
      { class: 'ft' },
      el(doc, 'p', { class: 'hint' }, t('ui-overlay-blocked-hint')),
      allow,
      keep,
    ),
  );

  // Enter keeps it blocked wherever focus is (except on the onion's <summary>, where it toggles).
  dialog.addEventListener(
    'keydown',
    (event) => {
      if (event.key !== 'Enter') return;
      const target = event.composedPath()[0] as HTMLElement | undefined;
      if (target?.tagName === 'SUMMARY') return;
      event.preventDefault();
      f.settle('keep-blocked');
    },
    true,
  );
  keep.focus();
  return f.promise;
}

/**
 * The user is pasting text that contains secrets. Resolves `masked` (default, Enter),
 * `cancel` (Esc) or `original` (only by clicking / Space on that button — never by Enter).
 */
export function showPasteConfirm(report: Report, opts: OverlayOptions = {}): Promise<PasteChoice> {
  const f = openFrame<PasteChoice>(opts, 'cancel', 'w');
  const { doc, dialog, t } = f;
  dialog.setAttribute('aria-labelledby', 'pw-t');
  dialog.setAttribute('aria-describedby', 'pw-d');

  const masked = el(doc, 'button', { type: 'button', class: 'pri' }, t('ui-overlay-paste-masked'));
  const original = el(
    doc,
    'button',
    { type: 'button', class: 'dan' },
    t('ui-overlay-paste-original'),
  );
  const cancel = el(doc, 'button', { type: 'button' }, t('ui-overlay-paste-cancel'));
  masked.addEventListener('click', () => f.settle('masked'));
  cancel.addEventListener('click', () => f.settle('cancel'));
  original.addEventListener('click', (event) => {
    if (f.trusted(event)) f.settle('original');
  });
  f.arm(original);

  dialog.append(
    header(f, 'pw-t', t('ui-overlay-paste-title'), ICON_WARN),
    el(
      doc,
      'div',
      { class: 'bdy' },
      el(doc, 'p', { id: 'pw-d' }, t('ui-overlay-paste-body', { count: report.secrets.length })),
      report.secrets.length > 0 &&
        el(
          doc,
          'ul',
          { class: 'sec' },
          ...report.secrets.map((s) =>
            el(doc, 'li', {}, el(doc, 'span', {}, s.label), el(doc, 'code', {}, s.masked)),
          ),
        ),
    ),
    el(
      doc,
      'div',
      { class: 'ft' },
      el(doc, 'p', { class: 'hint' }, t('ui-overlay-paste-hint')),
      cancel,
      original,
      masked,
    ),
  );

  // Enter always means "masked", even with focus on "original" (capture phase runs first and
  // preventDefault stops the button's own activation).
  dialog.addEventListener(
    'keydown',
    (event) => {
      if (event.key !== 'Enter') return;
      event.preventDefault();
      f.settle('masked');
    },
    true,
  );
  masked.focus();
  return f.promise;
}

/** Closes whatever overlay is open, resolving it with its safe choice. */
export function closeOverlay(): void {
  active?.close();
}
