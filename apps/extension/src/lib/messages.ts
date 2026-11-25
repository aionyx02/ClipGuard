// runtime / tabs messages between the content script, background, popup and offscreen document.
// Extension-internal only (no externally_connectable): web pages can't send these.
import type { Locale, Report } from '@paste-warden/core/types';
import type { NativeRecord, VerdictInfo } from './native';
import type { BlockRecord } from './settings';

/** content / options → background */
export type ToBackground =
  | { type: 'record'; record: BlockRecord; verdict?: VerdictInfo }
  /** Desktop link state (probes first if one is due). Replies with a `NativeRecord`. */
  | { type: 'native-status' }
  /** Probe the desktop app now. Replies with a `NativeRecord`. */
  | { type: 'native-probe' }
  | { type: 'present-blocked'; report: Report; url: string; locale: Locale; original: string }
  | { type: 'present-warning'; locale: Locale; kind: 'warning' | 'pastejack'; reasons: string[] }
  | { type: 'clipboard-write'; text: string };

/** background / popup → content (top frame) */
export type ToContent =
  | { type: 'show-blocked'; report: Report; url: string; locale: Locale; original: string }
  | { type: 'show-warning'; locale: Locale; kind: 'warning' | 'pastejack'; reasons: string[] }
  | { type: 'status' };

/** background → offscreen (Chrome) */
export interface ToOffscreen {
  target: 'offscreen';
  type: 'offscreen-write';
  text: string;
}

export type NativeStatusReply = NativeRecord;

/** Reply to `status`. */
export interface TabStatus {
  host: string;
  enabled: boolean;
  /** On the allowlist. */
  paused: boolean;
  blocked: number;
  warned: number;
  backend: 'wasm' | 'wasm2js' | null;
}
