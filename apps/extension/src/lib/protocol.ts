// What crosses the MAIN world ↔ isolated world boundary (docs/THREAT_MODEL.md T17).
//
// MAIN → isolated: only the text the page is writing and which API it used.
// isolated → MAIN: only the decision and, when blocked, the rendered harmless notice.
// No settings, no report, no other page's data ever goes back to the page's world.

/** Which clipboard-writing API the page used. */
export type Via =
  | 'writeText'
  | 'write'
  | 'setData'
  | 'itemsAdd'
  | 'execCommand'
  /** A same-origin child frame reached through contentWindow (T18). */
  | 'frame';

export interface WriteRequest {
  via: Via;
  text: string;
  /** The text is HTML (`text/html`); the isolated side extracts the text before analysis. */
  html?: boolean;
}

/**
 * - `allow`: write the page's text unchanged.
 * - `block`: write `notice` instead.
 * - `wait`: the engine is still loading; async callers wait for the `id`-tagged answer,
 *   sync callers let the write through (the isolated side re-checks and overwrites it).
 */
export type Reply = { v: 'allow' } | { v: 'block'; notice: string } | { v: 'wait'; id: number };

/** A synchronous verdict for one write. Must never throw. */
export type Ask = (req: WriteRequest) => Reply;

/** Resolves a `wait` reply. */
export type AwaitReply = (id: number) => Promise<Reply>;

/** Fixed event names used once per page for the handshake that agrees on the random names. */
export const HELLO_EVENT = 'paste-warden:hello';
export const READY_EVENT = 'paste-warden:ready';

/** Hard cap on what the page may send per request (the engine reads at most 1 Mi chars). */
export const MAX_REQUEST_CHARS = 1_048_576 + 16;
