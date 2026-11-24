import { useCallback, useEffect, useId, useRef, useState } from 'react';
import { useT } from '../i18n/LocaleProvider';
import type { Action, TraceStep } from '../report';
import { mediaMatches } from '../storage';
import { cx, TONE } from './icons';

const REDUCED_MOTION = '(prefers-reduced-motion: reduce)';

export interface OnionTraceProps {
  trace: TraceStep[];
  /** Reveal layers one by one on mount. Ignored (everything shown) under reduced motion. */
  autoPlay?: boolean;
  /** Delay between layers while playing, ms. */
  intervalMs?: number;
  /** Colours the innermost layer (usually the report's action). */
  tone?: Action;
  headingLevel?: 2 | 3 | 4;
  className?: string;
}

interface LayerProps {
  trace: TraceStep[];
  index: number;
  shown: number;
  tone: Action;
}

/** One layer of the onion; the next layer is nested inside it, like the obfuscation itself. */
function Layer({ trace, index, shown, tone }: LayerProps) {
  const t = useT();
  const step = trace[index];
  if (!step || index >= shown) return null;
  const innermost = index === trace.length - 1;
  const toneClasses = TONE[tone];
  return (
    <li
      data-layer={index + 1}
      data-kind={step.kind}
      className={cx(
        'motion-safe:animate-peel rounded-[10px] border p-3',
        innermost
          ? cx(toneClasses.border, toneClasses.bg)
          : index % 2 === 0
            ? 'border-line bg-surface'
            : 'border-line bg-surface-2',
      )}
    >
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-sm">
        <span className="inline-flex h-6 min-w-6 items-center justify-center rounded-full bg-ink-900 px-2 text-xs font-semibold text-brand-300 tabular-nums dark:bg-brand-300 dark:text-ink-900">
          {t('ui-comp-onion-layer', { n: index + 1 })}
        </span>
        <code className="rounded border border-line bg-surface px-1.5 py-px font-mono text-xs text-fg-muted">
          {step.kind}
        </code>
        <span className="text-fg">{step.text}</span>
      </div>
      {innermost && (
        <p className={cx('mt-2 text-xs font-semibold', toneClasses.text)}>
          {t('ui-comp-onion-result')}
        </p>
      )}
      <pre className="mt-2 overflow-x-auto rounded-md bg-ink-900 px-3 py-2 dark:bg-ink-950 font-mono text-[13px] leading-relaxed whitespace-pre-wrap break-all text-ink-100">
        {step.preview}
      </pre>
      {index + 1 < shown && (
        <ol className="mt-3 pl-2 sm:pl-3">
          <Layer trace={trace} index={index + 1} shown={shown} tone={tone} />
        </ol>
      )}
    </li>
  );
}

/**
 * The deobfuscation trace as nested layers ("onion view"), revealed step by step.
 *
 * Accessibility: real nested lists (screen readers announce the depth), plain buttons for
 * control, a polite live region that reads each newly revealed layer, and no animation or
 * auto-play under `prefers-reduced-motion`.
 */
export function OnionTrace({
  trace,
  autoPlay = true,
  intervalMs = 650,
  tone = 'quarantine',
  headingLevel = 2,
  className,
}: OnionTraceProps) {
  const t = useT();
  const id = useId();
  const total = trace.length;
  const [reduced] = useState(() => mediaMatches(REDUCED_MOTION));
  const [shown, setShown] = useState(() => (autoPlay && !reduced ? Math.min(1, total) : total));
  const [playing, setPlaying] = useState(autoPlay && !reduced && total > 1);
  const [announcement, setAnnouncement] = useState('');
  const announceRef = useRef(false);
  const shownRef = useRef(shown);
  shownRef.current = shown;

  // A new report restarts the reveal.
  const traceKey = trace.map((s) => `${s.kind}:${s.preview}`).join('\u0000');
  const lastKey = useRef(traceKey);
  useEffect(() => {
    if (lastKey.current === traceKey) return;
    lastKey.current = traceKey;
    const play = autoPlay && !reduced;
    setShown(play ? Math.min(1, total) : total);
    setPlaying(play && total > 1);
    setAnnouncement('');
    announceRef.current = false;
  }, [traceKey, autoPlay, reduced, total]);

  useEffect(() => {
    if (!playing) return;
    if (shown >= total) {
      setPlaying(false);
      return;
    }
    const timer = setTimeout(() => setShown((n) => Math.min(n + 1, total)), intervalMs);
    return () => clearTimeout(timer);
  }, [playing, shown, total, intervalMs]);

  // Announce only layers the user asked for; auto-play would otherwise talk over everything.
  useEffect(() => {
    if (!announceRef.current) return;
    const step = trace[shown - 1];
    if (step) {
      setAnnouncement(
        t('ui-comp-onion-announce', { n: shown, text: step.text, preview: step.preview }),
      );
    }
  }, [shown, trace, t]);

  // Buttons use aria-disabled (not disabled) so keyboard focus is not lost at the last layer.
  const next = useCallback(() => {
    if (shownRef.current >= total) return;
    announceRef.current = true;
    setPlaying(false);
    setShown((n) => Math.min(n + 1, total));
  }, [total]);
  const all = useCallback(() => {
    if (shownRef.current >= total) return;
    announceRef.current = false;
    setPlaying(false);
    setShown(total);
    setAnnouncement(t('ui-comp-onion-progress', { shown: total, total }));
  }, [total, t]);
  const replay = useCallback(() => {
    if (shownRef.current <= 1) return;
    announceRef.current = reduced;
    setAnnouncement('');
    setShown(Math.min(1, total));
    setPlaying(!reduced && total > 1);
  }, [reduced, total]);

  const layerNumbers = trace.map((_, i) => i + 1);
  const Heading = `h${headingLevel}` as const;
  const done = shown >= total;

  return (
    <section
      aria-labelledby={`${id}-title`}
      className={cx(
        'rounded-card border border-line bg-surface p-5 text-fg shadow-card',
        className,
      )}
    >
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <Heading id={`${id}-title`} className="flex items-center gap-2 text-lg font-semibold">
            <OnionGlyph className="size-5 text-accent" />
            {t('ui-comp-onion-title')}
          </Heading>
          <p className="mt-0.5 text-sm text-fg-muted">{t('ui-comp-onion-subtitle')}</p>
        </div>
        {total > 0 && (
          <div className="flex flex-wrap gap-2">
            <button type="button" onClick={next} aria-disabled={done} className={BUTTON_PRIMARY}>
              {t('ui-comp-onion-next')}
            </button>
            <button type="button" onClick={all} aria-disabled={done} className={BUTTON}>
              {t('ui-comp-onion-all')}
            </button>
            <button type="button" onClick={replay} aria-disabled={shown <= 1} className={BUTTON}>
              {t('ui-comp-onion-replay')}
            </button>
          </div>
        )}
      </div>

      {total === 0 ? (
        <p className="mt-4 text-sm text-fg-muted">{t('ui-comp-onion-empty')}</p>
      ) : (
        <>
          <p className="mt-4 text-xs text-fg-muted tabular-nums" id={`${id}-progress`}>
            {t('ui-comp-onion-progress', { shown, total })}
          </p>
          <div aria-hidden="true" className="mt-1.5 flex gap-1" data-testid="onion-progress-dots">
            {layerNumbers.map((n) => (
              <span
                key={n}
                className={cx(
                  'h-1 flex-1 rounded-full transition-colors duration-300',
                  n <= shown ? 'bg-accent' : 'bg-line',
                )}
              />
            ))}
          </div>
          <ol className="mt-3" aria-describedby={`${id}-progress`}>
            <Layer trace={trace} index={0} shown={shown} tone={tone} />
          </ol>
        </>
      )}
      <p aria-live="polite" aria-atomic="true" className="sr-only">
        {announcement}
      </p>
    </section>
  );
}

const BUTTON_BASE =
  'inline-flex h-8 items-center rounded-lg px-3 text-sm font-medium transition-colors aria-disabled:cursor-not-allowed aria-disabled:opacity-45';
const BUTTON_PRIMARY = cx(BUTTON_BASE, 'bg-accent text-accent-fg hover:opacity-90');
const BUTTON = cx(BUTTON_BASE, 'border border-line bg-surface text-fg hover:bg-surface-2');

function OnionGlyph({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 24 24"
      className={className}
      aria-hidden="true"
      focusable="false"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
    >
      <circle cx="12" cy="12" r="9" />
      <circle cx="12" cy="12" r="5.5" />
      <circle cx="12" cy="12" r="2" fill="currentColor" />
    </svg>
  );
}
