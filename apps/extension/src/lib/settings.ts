// Extension settings (docs/plan/phase-3.md §3.3). Stored in `storage.local` under `settings`;
// missing keys take the strict defaults, so an old or partial object is always usable.
import type { Settings as EngineSettings, Locale } from '@paste-warden/core/types';

export type LocaleMode = 'system' | Locale;
export type ThemeMode = 'system' | 'light' | 'dark';

/** PII packs (rules/pii-*.json). `universal` is always on. */
export const PACKS = ['universal', 'tw', 'cn', 'jp', 'kr', 'hk', 'sg', 'us'] as const;
export type Pack = (typeof PACKS)[number];

export interface ExtSettings {
  /** Master switch. */
  enabled: boolean;
  /** Replace quarantined clipboard writes with a notice and show the blocked dialog. */
  guardWrites: boolean;
  /** Confirm before pasting secrets. */
  guardPaste: boolean;
  /** Compare the selection with what the page writes on copy. */
  pastejack: boolean;
  /** Engine strictness (crates/core `Settings`). */
  block_malicious_commands: boolean;
  warn_suspicious_commands: boolean;
  detect_secrets: boolean;
  detect_hidden_chars: boolean;
  /** `null` = derived from navigator.languages (§5.6); otherwise the user's choice. */
  packs: Pack[] | null;
  locale: LocaleMode;
  theme: ThemeMode;
  /** Hostnames where PasteWarden stays out (a.example also covers sub.a.example). */
  allowlist: string[];
}

export const DEFAULT_SETTINGS: ExtSettings = {
  enabled: true,
  guardWrites: true,
  guardPaste: true,
  pastejack: true,
  block_malicious_commands: true,
  warn_suspicious_commands: true,
  detect_secrets: true,
  detect_hidden_chars: true,
  packs: null,
  locale: 'system',
  theme: 'system',
  allowlist: [],
};

export const SETTINGS_KEY = 'settings';
export const RECENT_KEY = 'recent';
/** How many recent blocks the popup keeps. */
export const RECENT_MAX = 20;

const bool = (v: unknown, d: boolean) => (typeof v === 'boolean' ? v : d);

/** Validates and fills a stored settings object. Never throws. */
export function normalizeSettings(raw: unknown): ExtSettings {
  const r = (raw && typeof raw === 'object' ? raw : {}) as Record<string, unknown>;
  const d = DEFAULT_SETTINGS;
  const packs = Array.isArray(r.packs)
    ? (r.packs.filter((p): p is Pack =>
        (PACKS as readonly string[]).includes(p as string),
      ) as Pack[])
    : null;
  const allowlist = Array.isArray(r.allowlist)
    ? r.allowlist
        .map((h) => (typeof h === 'string' ? normalizeHost(h) : ''))
        .filter((h): h is string => h !== '')
    : [];
  return {
    enabled: bool(r.enabled, d.enabled),
    guardWrites: bool(r.guardWrites, d.guardWrites),
    guardPaste: bool(r.guardPaste, d.guardPaste),
    pastejack: bool(r.pastejack, d.pastejack),
    block_malicious_commands: bool(r.block_malicious_commands, d.block_malicious_commands),
    warn_suspicious_commands: bool(r.warn_suspicious_commands, d.warn_suspicious_commands),
    detect_secrets: bool(r.detect_secrets, d.detect_secrets),
    detect_hidden_chars: bool(r.detect_hidden_chars, d.detect_hidden_chars),
    packs: packs && !packs.includes('universal') ? ['universal', ...packs] : packs,
    locale: r.locale === 'zh-TW' || r.locale === 'en' ? r.locale : 'system',
    theme: r.theme === 'light' || r.theme === 'dark' ? r.theme : 'system',
    allowlist: [...new Set(allowlist)],
  };
}

const REGION_PACK: Record<string, Pack> = {
  TW: 'tw',
  CN: 'cn',
  JP: 'jp',
  KR: 'kr',
  HK: 'hk',
  SG: 'sg',
  US: 'us',
};

/**
 * PII packs for the browser's preferred languages (docs/spec/detection-rules.md §5.6): the
 * region of every tag (`zh-TW`, `zh-Hant-HK`, `en_US`), plus `ja` → jp and `ko` → kr for tags
 * without a region. Union over all languages; `universal` always.
 */
export function packsForLanguages(languages: readonly string[] | undefined): Pack[] {
  const out = new Set<Pack>(['universal']);
  for (const tag of languages ?? []) {
    const parts = tag.replace(/_/g, '-').split('-');
    const region = parts.slice(1).find((p) => /^[A-Za-z]{2}$/.test(p));
    if (region) {
      const pack = REGION_PACK[region.toUpperCase()];
      if (pack) out.add(pack);
      continue;
    }
    const lang = parts[0]?.toLowerCase();
    if (lang === 'ja') out.add('jp');
    if (lang === 'ko') out.add('kr');
  }
  return PACKS.filter((p) => out.has(p));
}

export function effectivePacks(s: ExtSettings, languages: readonly string[] | undefined): Pack[] {
  return s.packs ?? packsForLanguages(languages);
}

/** The engine's `Settings` for these extension settings. */
export function engineSettings(
  s: ExtSettings,
  languages: readonly string[] | undefined,
): EngineSettings {
  return {
    block_malicious_commands: s.block_malicious_commands,
    warn_suspicious_commands: s.warn_suspicious_commands,
    detect_secrets: s.detect_secrets,
    detect_hidden_chars: s.detect_hidden_chars,
    packs: effectivePacks(s, languages),
    ai: { explain_commands: false },
  };
}

/** Lowercase hostname from a hostname or URL the user typed; '' if it isn't one. */
export function normalizeHost(input: string): string {
  let s = input.trim().toLowerCase();
  if (!s) return '';
  try {
    if (s.includes('://')) s = new URL(s).hostname;
  } catch {
    return '';
  }
  s = s.replace(/^\*\./, '').replace(/\.$/, '').split('/')[0] ?? '';
  s = s.replace(/:\d+$/, '');
  return /^[a-z0-9.-]+$/.test(s) && !s.startsWith('.') && !s.includes('..') ? s : '';
}

export function isAllowlisted(host: string, allowlist: readonly string[]): boolean {
  const h = host.toLowerCase().replace(/\.$/, '');
  if (!h) return false;
  return allowlist.some((entry) => h === entry || h.endsWith(`.${entry}`));
}

/** One entry of the popup's recent blocks: never the clipboard text (P3/P4). */
export interface BlockRecord {
  domain: string;
  /** ms since epoch. */
  time: number;
  kind: 'command' | 'warning' | 'pastejack' | 'secret';
  /** Masked values (secrets) or '' (commands: nothing of the text is kept). */
  masked: string;
}

export function isBlockRecord(v: unknown): v is BlockRecord {
  const r = v as BlockRecord;
  return (
    !!r &&
    typeof r.domain === 'string' &&
    typeof r.time === 'number' &&
    ['command', 'warning', 'pastejack', 'secret'].includes(r.kind) &&
    typeof r.masked === 'string'
  );
}
