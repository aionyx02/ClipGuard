// The isolated-world side: decides what happens to each clipboard write the MAIN-world hook
// reports, guards paste events, and tracks copies for pastejacking. Shared by the extension's
// content script and the userscript; everything platform-specific comes in through `GuardEnv`.
//
// docs/plan/phase-3.md §3.2, docs/spec/detection-rules.md §7.
import type { AnalyzeOptions, Locale, Report } from '@paste-warden/core/types';
import type { BlockedChoice, PasteChoice } from '@paste-warden/overlay';
import { compare, type PastejackReason } from './pastejack';
import type { Reply, WriteRequest } from './protocol';
import { type BlockRecord, type ExtSettings, engineSettings, isAllowlisted } from './settings';
import { pastejackReasonText, resolveLocale, type Translate, translator } from './strings';

export interface EngineApi {
  backend: 'wasm' | 'wasm2js';
  analyze(text: string, opts: AnalyzeOptions): Report;
  mask(text: string, report: Pick<Report, 'secrets'>, locale: Locale): string;
}

export interface BlockedEvent {
  report: Report;
  /** The frame the write came from. */
  url: string;
  locale: Locale;
  /** Kept in memory only for "allow once"; never stored or logged. */
  original: string;
}

export interface WarnEvent {
  locale: Locale;
  kind: 'warning' | 'pastejack';
  reasons: string[];
}

export interface GuardEnv {
  win: Window & typeof globalThis;
  settings(): ExtSettings;
  engine(): EngineApi | null;
  /** Show the blocked dialog (usually in the top frame). */
  presentBlocked(e: BlockedEvent): void;
  /** Show the non-blocking notice (usually in the top frame). */
  presentWarning(e: WarnEvent): void;
  /** Paste confirmation; runs in the frame that received the paste. */
  confirmPaste(report: Report, locale: Locale): Promise<PasteChoice>;
  /** Writes to the clipboard from the extension side (optimistic-path overwrite). */
  overwriteClipboard(text: string): Promise<boolean>;
  record(r: BlockRecord): void;
  /** Answers a `wait` reply. */
  resolveWait(id: number, reply: Reply): void;
  now?(): number;
  /** Schedules UI work after the current task (default `setTimeout(fn, 0)`; tests run it inline). */
  later?(fn: () => void): void;
}

/** Pastejacking window after a copy (legacy content.js: 2 s, no clicks or keys in between). */
export const PASTEJACK_WINDOW_MS = 2000;
/** Same text decided again within this window (text/plain + text/html of one copy) is silent. */
const DEDUPE_MS = 1500;

interface Pending {
  id: number;
  req: WriteRequest;
  sync: boolean;
}

export class Guard {
  private readonly env: GuardEnv;
  private readonly now: () => number;
  private lastCopy: { selection: string; time: number } | null = null;
  private lastInput = 0;
  private recent: { key: string; time: number; reply: Reply } | null = null;
  private pending: Pending[] = [];
  private nextId = 1;
  readonly stats = { blocked: 0, warned: 0 };

  constructor(env: GuardEnv) {
    this.env = env;
    this.now = env.now ?? (() => Date.now());
  }

  /** Registers the copy / input / paste listeners. Call at document_start. */
  attach(): void {
    const { win } = this.env;
    const onCopy = (e: Event) => {
      if (e.isTrusted) this.copied(selectionText(win));
    };
    const onInput = (e: Event) => {
      if (!e.isTrusted) return;
      if (e instanceof win.KeyboardEvent && ['Control', 'Meta', 'Shift', 'Alt'].includes(e.key))
        return;
      this.inputSeen();
    };
    win.addEventListener('copy', onCopy, true);
    win.addEventListener('cut', onCopy, true);
    win.addEventListener('pointerdown', onInput, true);
    win.addEventListener('keydown', onInput, true);
    win.addEventListener('paste', (e) => this.onPaste(e as ClipboardEvent), true);
  }

  /** The user copied `selection` (a trusted copy / cut event). */
  copied(selection: string): void {
    this.lastCopy = { selection, time: this.now() };
  }

  /** The user clicked or pressed a key (ends the pastejacking window of the last copy). */
  inputSeen(): void {
    this.lastInput = this.now();
  }

  /** True when PasteWarden should act on this frame at all. */
  active(s: ExtSettings = this.env.settings()): boolean {
    return s.enabled && !isAllowlisted(this.env.win.location.hostname, s.allowlist);
  }

  locale(s: ExtSettings = this.env.settings()): Locale {
    return resolveLocale(s.locale, this.env.win.navigator.languages);
  }

  t(s?: ExtSettings): Translate {
    return translator(this.locale(s));
  }

  /** The rendered harmless notice (also handed to MAIN at the handshake as the fail-closed text). */
  notice(): string {
    return this.t()('ui-ext-clipboard-notice');
  }

  /** Called synchronously for every write the page makes. Never throws. */
  onWrite(req: WriteRequest): Reply {
    try {
      return this.decide(req, true);
    } catch (err) {
      console.warn('[PasteWarden] write check failed:', (err as Error)?.name ?? 'Error');
      return { v: 'allow' };
    }
  }

  /** The engine finished loading: answer everything that waited for it. */
  engineReady(): void {
    const queued = this.pending.splice(0);
    for (const p of queued) {
      let reply: Reply;
      try {
        reply = this.decide(p.req, false);
      } catch {
        reply = { v: 'allow' };
      }
      if (p.sync) {
        // The write already went through (optimistic path): overwrite it if it was bad.
        if (reply.v === 'block') void this.env.overwriteClipboard(reply.notice);
      } else {
        this.env.resolveWait(p.id, reply);
      }
    }
  }

  private decide(req: WriteRequest, first: boolean): Reply {
    const s = this.env.settings();
    if (!this.active(s) || (!s.guardWrites && !s.pastejack && !s.detect_hidden_chars)) {
      return { v: 'allow' };
    }
    const text = req.html ? htmlToText(this.env.win, req.text) : req.text;
    if (!text.trim()) return { v: 'allow' };

    const key = `${req.via === 'execCommand' ? 'x' : 'w'}:${text.replace(/\s+/g, ' ').trim()}`;
    const now = this.now();
    if (this.recent && this.recent.key === key && now - this.recent.time < DEDUPE_MS) {
      return this.recent.reply;
    }

    const engine = this.env.engine();
    if (!engine) {
      if (!first) return { v: 'allow' };
      const id = this.nextId++;
      this.pending.push({ id, req, sync: !isAsyncVia(req.via) });
      return { v: 'wait', id };
    }

    const locale = this.locale(s);
    const t = translator(locale);
    const langs = this.env.win.navigator.languages;
    const report = engine.analyze(text, {
      context: { sourceKind: 'browser', url: this.env.win.location.href, platform: 'web' },
      // A page putting a secret on the clipboard (an API key "copy" button) is not an attack;
      // secrets are guarded when they are pasted.
      settings: { ...engineSettings(s, langs), detect_secrets: false },
      locale,
    });

    let reply: Reply = { v: 'allow' };
    if (report.action === 'quarantine' && s.guardWrites) {
      reply = { v: 'block', notice: t('ui-ext-clipboard-notice') };
      this.stats.blocked++;
      this.env.record(this.recordOf('command', ''));
      const event: BlockedEvent = {
        report,
        url: this.env.win.location.href,
        locale,
        original: text,
      };
      this.later(() => this.env.presentBlocked(event));
    } else {
      const reasons: string[] = [];
      let kind: WarnEvent['kind'] = 'warning';
      if (report.action !== 'allow') {
        reasons.push(
          ...report.command.reasons.map((r) => r.text),
          ...report.hidden.reasons.map((r) => r.text),
        );
      }
      if (s.pastejack) {
        const selection = this.selectionFor(req.via, now);
        if (selection !== null) {
          const pj = compare(selection, text);
          if (pj.warn) {
            kind = 'pastejack';
            reasons.unshift(...pj.reasons.map((r: PastejackReason) => pastejackReasonText(t, r)));
          }
        }
      }
      if (reasons.length > 0) {
        this.stats.warned++;
        this.env.record(this.recordOf(kind, ''));
        const event: WarnEvent = { locale, kind, reasons: [...new Set(reasons)] };
        this.later(() => this.env.presentWarning(event));
      }
    }
    this.recent = { key, time: now, reply };
    return reply;
  }

  /**
   * Selection to compare with for pastejacking, or null when this write isn't a copy:
   * clipboard-event writes use the selection at the copy; async writes only count within
   * 2 s of a copy with no click or key in between (legacy content.js).
   */
  private selectionFor(via: WriteRequest['via'], now: number): string | null {
    // execCommand('copy') without a handler copies the selection itself: nothing to compare.
    if (!this.lastCopy || via === 'execCommand') return null;
    if (!isAsyncVia(via)) return this.lastCopy.selection;
    if (now - this.lastCopy.time > PASTEJACK_WINDOW_MS) return null;
    if (this.lastInput > this.lastCopy.time) return null;
    return this.lastCopy.selection;
  }

  /**
   * UI after the page's write call has gone through: a dialog that takes focus first (in the top
   * document, for a write from a frame) would make that write fail with "Document is not focused".
   */
  private later(fn: () => void): void {
    if (this.env.later) this.env.later(fn);
    else this.env.win.setTimeout(fn, 0);
  }

  private recordOf(kind: BlockRecord['kind'], masked: string): BlockRecord {
    return { domain: this.env.win.location.hostname, time: this.now(), kind, masked };
  }

  /** Paste guard: only when secrets are found; never on password fields. */
  onPaste(event: ClipboardEvent): void {
    try {
      this.handlePaste(event);
    } catch (err) {
      console.warn('[PasteWarden] paste check failed:', (err as Error)?.name ?? 'Error');
    }
  }

  private handlePaste(event: ClipboardEvent): void {
    if (!event.isTrusted || event.defaultPrevented) return;
    const s = this.env.settings();
    if (!this.active(s) || !s.guardPaste || !s.detect_secrets) return;
    const target = editableTarget(event);
    if (!target) return;
    const text = event.clipboardData?.getData('text/plain') ?? '';
    if (!text.trim()) return;
    const engine = this.env.engine();
    if (!engine) return;
    const locale = this.locale(s);
    const report = engine.analyze(text, {
      context: { sourceKind: 'browser', url: this.env.win.location.href, platform: 'web' },
      settings: engineSettings(s, this.env.win.navigator.languages),
      locale,
    });
    if (report.secrets.length === 0) return;

    // Stop the paste before any page handler can read the clipboard data.
    event.preventDefault();
    event.stopImmediatePropagation();
    const restore = saveSelection(this.env.win, target);
    this.env.record(
      this.recordOf(
        'secret',
        report.secrets
          .map((x) => x.masked)
          .join(' ')
          .slice(0, 200),
      ),
    );
    void this.env.confirmPaste(report, locale).then((choice) => {
      if (choice === 'cancel') {
        restore();
        return;
      }
      const value = choice === 'masked' ? engine.mask(text, report, locale) : text;
      restore();
      insertText(this.env.win, target, value);
    });
  }
}

function isAsyncVia(via: WriteRequest['via']): boolean {
  return via === 'writeText' || via === 'write';
}

/** Text of an HTML clipboard payload, parsed inertly (no scripts, no resource loads). */
export function htmlToText(win: Window & typeof globalThis, html: string): string {
  try {
    const doc = new win.DOMParser().parseFromString(html, 'text/html');
    return doc.body?.textContent ?? '';
  } catch {
    return html;
  }
}

/** What the default copy action takes: the focused field's selection, else the page selection. */
export function selectionText(win: Window & typeof globalThis): string {
  try {
    let active = win.document.activeElement;
    while (active?.shadowRoot?.activeElement) active = active.shadowRoot.activeElement;
    if (active instanceof win.HTMLTextAreaElement || active instanceof win.HTMLInputElement) {
      const start = active.selectionStart;
      const end = active.selectionEnd;
      if (start !== null && end !== null && end > start) return active.value.slice(start, end);
    }
    return win.getSelection()?.toString() ?? '';
  } catch {
    return '';
  }
}

const TEXT_INPUTS = new Set(['text', 'search', 'url', 'email', 'tel', '']);

type Editable = HTMLInputElement | HTMLTextAreaElement | HTMLElement;

/** The editable element the paste goes into, or null (not editable, or a password field). */
export function editableTarget(event: Event): Editable | null {
  const path = event.composedPath();
  const first = path[0];
  if (!(first instanceof Element)) return null;
  const el = first as HTMLElement;
  const tag = el.localName;
  if (tag === 'input') {
    const input = el as HTMLInputElement;
    const type = (input.getAttribute('type') ?? '').toLowerCase();
    if (type === 'password' || input.type === 'password') return null;
    return TEXT_INPUTS.has(type) && !input.readOnly && !input.disabled ? input : null;
  }
  if (tag === 'textarea') {
    const ta = el as HTMLTextAreaElement;
    return ta.readOnly || ta.disabled ? null : ta;
  }
  const host = el.isContentEditable
    ? el
    : (el.closest?.('[contenteditable]') as HTMLElement | null);
  return host?.isContentEditable ? host : null;
}

function isField(el: Editable): el is HTMLInputElement | HTMLTextAreaElement {
  return el.localName === 'input' || el.localName === 'textarea';
}

/** Remembers the caret / selection so it can be put back after the dialog closes. */
function saveSelection(win: Window & typeof globalThis, target: Editable): () => void {
  if (isField(target)) {
    const start = target.selectionStart;
    const end = target.selectionEnd;
    return () => {
      target.focus({ preventScroll: true });
      if (start !== null && end !== null) {
        try {
          target.setSelectionRange(start, end);
        } catch {
          // Some input types don't support selection ranges.
        }
      }
    };
  }
  const sel = win.getSelection();
  const range = sel && sel.rangeCount > 0 ? sel.getRangeAt(0).cloneRange() : null;
  return () => {
    target.focus({ preventScroll: true });
    if (range) {
      const s = win.getSelection();
      s?.removeAllRanges();
      s?.addRange(range);
    }
  };
}

/** Inserts like a paste would (undo history, input events); falls back to setRangeText. */
export function insertText(win: Window & typeof globalThis, target: Editable, value: string): void {
  let ok = false;
  try {
    ok = win.document.execCommand('insertText', false, value);
  } catch {
    ok = false;
  }
  if (ok) return;
  if (isField(target)) {
    const start = target.selectionStart ?? target.value.length;
    const end = target.selectionEnd ?? start;
    target.setRangeText(value, start, end, 'end');
    target.dispatchEvent(
      new win.InputEvent('input', { bubbles: true, inputType: 'insertFromPaste' }),
    );
    return;
  }
  const sel = win.getSelection();
  if (sel && sel.rangeCount > 0) {
    const range = sel.getRangeAt(0);
    range.deleteContents();
    range.insertNode(win.document.createTextNode(value));
    range.collapse(false);
    target.dispatchEvent(
      new win.InputEvent('input', { bubbles: true, inputType: 'insertFromPaste' }),
    );
  }
}

/** Default `confirmPaste` / blocked presentation using @paste-warden/overlay in this frame. */
export type { BlockedChoice, PasteChoice };
