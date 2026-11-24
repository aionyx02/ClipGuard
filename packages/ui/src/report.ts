/**
 * Report JSON shape shared by the CLI (`--json`), MCP and WASM — docs/plan/phase-2.md §2.2.
 *
 * KEEP IN SYNC: this is a local copy so `@paste-warden/ui` can be built and tested before
 * `@paste-warden/core` exists. It MUST match `packages/core-js/src/types.ts`; once that package
 * lands, replace this file with `export type * from '@paste-warden/core'`.
 *
 * Privacy (P4): a Report never contains secret plaintext — only masked strings and positions.
 */

export type Action = 'allow' | 'warn' | 'quarantine';
export type CommandLevel = 'none' | 'suspicious' | 'malicious';
export type HiddenLevel = 'none' | 'suspicious';
export type Locale = 'zh-TW' | 'en';

/** A translated reason (`text` is already rendered in the locale passed to `analyze`). */
export interface Reason {
  id: string;
  text: string;
}

/**
 * One deobfuscation step. `kind` is the snake_case `StepKind` name from
 * `crates/core/src/command/deobfuscate` (`caret`, `backtick`, `concat`, `base64`, …);
 * `text` describes the step (translated); `preview` is the result after the step, masked.
 */
export interface TraceStep {
  kind: string;
  text: string;
  preview: string;
}

export interface CommandFinding {
  level: CommandLevel;
  /** 0–100, formula in docs/spec/detection-rules.md §3.6. */
  risk_score: number;
  reasons: Reason[];
  trace: TraceStep[];
  hosts: string[];
}

export interface SecretFinding {
  kind: string;
  rule_id: string;
  /** Translated label (e.g. 身分證字號). */
  label: string;
  /** Masked value — never the plaintext. */
  masked: string;
  /** UTF-16 [start, end) in the analyzed text. */
  span_utf16: [number, number];
}

export interface HiddenFinding {
  level: HiddenLevel;
  reasons: Reason[];
}

export interface WalletFinding {
  currency: string;
  span_utf16: [number, number];
}

export interface Report {
  schema: 1;
  action: Action;
  truncated: boolean;
  command: CommandFinding;
  secrets: SecretFinding[];
  hidden: HiddenFinding;
  wallets: WalletFinding[];
}
