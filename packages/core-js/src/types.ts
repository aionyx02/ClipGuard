// Shared Report JSON (docs/plan/phase-2.md §2.2). Also the schema source for the
// MCP tool output. Field names are snake_case on purpose: this is the same JSON
// the CLI (`--json`), MCP server, WASM and Python bindings emit.

/** UI locales shipped with PasteWarden. */
export type Locale = 'zh-TW' | 'en';

/** What the app should do with the clipboard content. */
export type Action = 'allow' | 'warn' | 'quarantine';

export type CommandLevel = 'none' | 'suspicious' | 'malicious';

/** A localized reason: Fluent message id plus the text rendered in the requested locale. */
export interface Reason {
  id: string;
  text: string;
}

/** Deobfuscation step kinds (`StepKind::as_str` in crates/core). */
export type TraceKind =
  | 'invisible'
  | 'dash'
  | 'caret'
  | 'variable'
  | 'quote'
  | 'program_path'
  | 'markdown'
  | 'full_width'
  | 'backtick'
  | 'url_decode'
  | 'hex_decode'
  | 'char_code'
  | 'concat'
  | 'join'
  | 'format'
  | 'replace'
  | 'string_method'
  | 'ps_variable'
  | 'unwrap'
  | 'base64'
  | 'encoded_command'
  | 'cmd_substring'
  | 'nested_variable';

export interface TraceStep {
  kind: TraceKind;
  /** What the step did, localized. */
  text: string;
  /** Text after the step around the first change; secrets masked. Untrusted: escape before display. */
  preview: string;
}

export interface CommandReport {
  level: CommandLevel;
  /** 0–100 (docs/spec/detection-rules.md §3.6); inside the band of `level`. */
  risk_score: number;
  reasons: Reason[];
  trace: TraceStep[];
  /** Download hosts, lowercase, in order of appearance. */
  hosts: string[];
}

export type SecretKind =
  | 'national_id'
  | 'resident_certificate'
  | 'business_id'
  | 'credit_card'
  | 'mobile_phone'
  | 'api_key'
  | 'registered'
  | 'phone_number'
  | 'bank_account'
  | 'mnemonic';

/** `[start, length]` in UTF-16 code units (JS string indices). */
export type SpanUtf16 = [start: number, length: number];

export interface SecretFinding {
  kind: SecretKind;
  /** Rule id (`tw-national-id`, `gitleaks.…`); empty for registered secrets. */
  rule_id: string;
  /** Localized display label. */
  label: string;
  /** Masked value (`A12****789`). The plaintext is never in the report. */
  masked: string;
  span_utf16: SpanUtf16;
}

export interface HiddenReport {
  level: 'none' | 'suspicious';
  reasons: Reason[];
}

export type Currency = 'bitcoin' | 'ethereum' | 'tron' | 'solana' | 'xrp';

export interface WalletFinding {
  currency: Currency;
  span_utf16: SpanUtf16;
}

/** Everything the engine found in one piece of text. */
export interface Report {
  schema: 1;
  action: Action;
  /** Only the first 1 Mi chars were analyzed. */
  truncated: boolean;
  command: CommandReport;
  secrets: SecretFinding[];
  hidden: HiddenReport;
  wallets: WalletFinding[];
}

/** User settings (crates/core `Settings`). Missing keys take the strict defaults. */
export interface Settings {
  block_malicious_commands: boolean;
  warn_suspicious_commands: boolean;
  detect_secrets: boolean;
  detect_hidden_chars: boolean;
  /** PII packs (`universal`, `tw`, `us`, …). Empty = `universal` + `tw`. */
  packs: string[];
  ai: { explain_commands: boolean };
}

export type SourceKind =
  | 'browser'
  | 'terminal'
  | 'ide'
  | 'chat'
  | 'password_manager'
  | 'other'
  | 'unknown';

export type Platform = 'windows' | 'macos' | 'linux' | 'android' | 'ios' | 'web' | 'unknown';

export interface AnalyzeOptions {
  /** Where the text came from. Weighs `risk_score` only; never lowers a verdict. URLs are private: never log them. */
  context?: { sourceKind?: SourceKind; url?: string; app?: string; platform?: Platform };
  settings?: Partial<Settings>;
  /** Locale of `text` / `label` fields. Default `zh-TW`. */
  locale?: Locale;
}

/** Result of `deobfuscate`. */
export interface Deobfuscated {
  trace: TraceStep[];
  /** Start of the fully peeled text, secrets masked. Untrusted: escape before display. */
  output_preview: string;
  /** A safety cap stopped peeling early. */
  capped: boolean;
}

/** Which engine build is loaded. */
export type Backend = 'wasm' | 'wasm2js';
