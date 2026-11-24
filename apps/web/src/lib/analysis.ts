import type { Locale, Report } from '@paste-warden/core';
import type { Core } from '../engine';

export interface Analysis {
  report: Report;
  /** `text` with every secret replaced by its mask; `undefined` when nothing was found. */
  masked: string | undefined;
  /** Wall time of analyze + mask, ms. */
  ms: number;
}

/** One synchronous pass through the engine. The text never leaves this function's caller. */
export function analyzeText(core: Core, text: string, locale: Locale): Analysis {
  const start = performance.now();
  // No context: the playground shows the verdict for the text alone.
  const report = core.analyze(text, { locale });
  const masked = report.secrets.length > 0 ? core.mask(text, report, locale) : undefined;
  return { report, masked, ms: performance.now() - start };
}

/** Whether the onion view has something to say for this report. */
export function showOnion(report: Report): boolean {
  return report.command.trace.length > 0 || report.command.level !== 'none';
}
