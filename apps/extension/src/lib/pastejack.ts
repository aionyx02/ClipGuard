// Pastejacking: the text the user selected vs what the page wrote to the clipboard
// (docs/spec/detection-rules.md §7, corpus/ops/pastejack.md).
//
// Port of crates/core/src/pastejack (itself the legacy extension's lib/pastejack.js). The engine's
// WASM API doesn't export it (it's a comparison of two texts the content script already has), so
// it lives here; the data is the same `rules/pastejack/*.json` and the corpus cases in
// corpus/cases/pastejack*.jsonl run against this file in test/pastejack.test.ts.
import hiddenChars from '../../../../rules/pastejack/hidden-chars.json';
import signalRules from '../../../../rules/pastejack/signals.json';

const HIDDEN: ReadonlyArray<readonly [number, number]> = hiddenChars.ranges.map(
  ([a = '', b = '']) => [parseInt(a.slice(2), 16), parseInt(b.slice(2), 16)] as const,
);

export function isHiddenChar(cp: number): boolean {
  if (cp < 0x80) return false;
  for (const [a, b] of HIDDEN) if (cp >= a && cp <= b) return true;
  return false;
}

type Matcher = (lower: string) => boolean;

/** `{b}` = ASCII word boundary, `{WS}` / `{NWS}` = JS `\s` / `\S` (rules/pastejack/signals.json). */
function expand(src: string): RegExp {
  return new RegExp(
    src.replaceAll('{b}', '\\b').replaceAll('{NWS}', '\\S').replaceAll('{WS}', '\\s'),
    'm',
  );
}

/** Program name called as a command: start / space / separator before, argument or end after. */
function invocation(names: readonly string[]): Matcher {
  const res = names.map(
    (n) =>
      new RegExp(
        `(?:^|[\\s;&|("'])${n.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?:\\.exe)?(?=\\s+[-/"'#a-z0-9]|\\s*$|\\s*[|;&])`,
        'm',
      ),
  );
  return (lower) => res.some((re) => re.test(lower));
}

export const SIGNALS: ReadonlyArray<{ id: string; match: Matcher }> = signalRules.signals.map(
  (s) => {
    const rule = s as { id: string; invocation?: string[]; regex?: string };
    if (rule.invocation) return { id: rule.id, match: invocation(rule.invocation) };
    const re = expand(rule.regex ?? '(?!)');
    return { id: rule.id, match: (lower: string) => re.test(lower) };
  },
);

const asciiLower = (s: string) => s.replace(/[A-Z]+/g, (m) => m.toLowerCase());

/** Command signal ids present in `text`, in rule order. */
export function commandSignals(text: string): string[] {
  if (!text) return [];
  const lower = asciiLower(text);
  return SIGNALS.filter((s) => s.match(lower)).map((s) => s.id);
}

function stripHidden(text: string): string {
  let out = '';
  for (const ch of text) if (!isHiddenChar(ch.codePointAt(0) ?? 0)) out += ch;
  return out;
}

function hiddenCount(text: string): number {
  let n = 0;
  for (const ch of text) if (isHiddenChar(ch.codePointAt(0) ?? 0)) n++;
  return n;
}

/** Drops invisible characters, collapses all whitespace runs (JS `\s`) to one space, trims. */
export function normalize(text: string): string {
  return stripHidden(text).replace(/\s+/g, ' ').trim();
}

export type CopyKind = 'empty' | 'same' | 'appended' | 'replaced' | 'unselected';

export interface PastejackReason {
  /** Fluent id in locales/<lang>/pastejack.ftl. */
  id: 'pastejack-hidden' | 'pastejack-added' | 'pastejack-newline' | 'pastejack-replaced';
  signal?: string;
}

export interface PastejackVerdict {
  kind: CopyKind;
  warn: boolean;
  reasons: PastejackReason[];
}

export function compare(selection: string, written: string): PastejackVerdict {
  const sel = normalize(selection);
  const wr = normalize(written);
  const reasons: PastejackReason[] = [];
  const writtenHidden = hiddenCount(written);
  if (wr === '' && writtenHidden === 0) return { kind: 'empty', warn: false, reasons };

  const newHidden = writtenHidden > hiddenCount(selection);
  if (newHidden) reasons.push({ id: 'pastejack-hidden' });

  const selSignals = commandSignals(selection);
  const added = commandSignals(written).filter((s) => !selSignals.includes(s));
  const newlineExec =
    written.trim().includes('\n') && !selection.trim().includes('\n') && added.length > 0;
  for (const signal of added) reasons.push({ id: 'pastejack-added', signal });
  if (newlineExec) reasons.push({ id: 'pastejack-newline' });

  if (sel === '') return { kind: 'unselected', warn: added.length > 0 || newHidden, reasons };
  if (sel === wr) return { kind: 'same', warn: newHidden, reasons };
  if (wr.includes(sel)) return { kind: 'appended', warn: reasons.length > 0, reasons };
  reasons.unshift({ id: 'pastejack-replaced' });
  return { kind: 'replaced', warn: true, reasons };
}

/** Invisible characters shown as ⟦U+XXXX⟧, cut to `max` UTF-16 units plus `…`. */
export function preview(text: string, max = 160): string {
  let visible = '';
  for (const ch of text) {
    const cp = ch.codePointAt(0) ?? 0;
    visible += isHiddenChar(cp) ? `⟦U+${cp.toString(16).toUpperCase().padStart(4, '0')}⟧` : ch;
  }
  if (visible.length <= max) return visible;
  let cut = visible.slice(0, max);
  const last = cut.charCodeAt(cut.length - 1);
  if (last >= 0xd800 && last <= 0xdbff) cut = cut.slice(0, -1);
  return `${cut}…`;
}
