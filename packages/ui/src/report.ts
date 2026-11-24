/**
 * Report JSON shape shared by the CLI (`--json`), MCP and WASM — docs/plan/phase-2.md §2.2.
 *
 * The single source of truth is `packages/core-js/src/types.ts`; this module only re-exports it
 * (type-only, so `@paste-warden/ui` never pulls the engine into a bundle).
 *
 * Privacy (P4): a Report never contains secret plaintext — only masked strings and positions.
 */

import type { CommandReport, HiddenReport } from '@paste-warden/core';

export type * from '@paste-warden/core';

/** @deprecated Old local name; use `CommandReport`. */
export type CommandFinding = CommandReport;
/** @deprecated Old local name; use `HiddenReport`. */
export type HiddenFinding = HiddenReport;
export type HiddenLevel = HiddenReport['level'];
