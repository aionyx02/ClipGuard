import {
  MaskPreview,
  OnionTrace,
  SecretList,
  type Translate,
  useLocale,
  VerdictCard,
} from '@paste-warden/ui';
import { useDeferredValue, useEffect, useId, useMemo, useRef, useState } from 'react';
import { type Analysis, analyzeText, showOnion } from '../lib/analysis';
import { buildExample, EXAMPLE_IDS, type ExampleId } from '../lib/samples';
import { button, CARD } from '../park/recipes';
import type { EngineState } from '../useEngine';
import { CopyIcon } from './icons';

const BUTTON = button({ variant: 'surface', size: 'sm' });

export function Playground({ engine }: { engine: EngineState }) {
  const { t, locale } = useLocale();
  const ids = useId();
  const [text, setText] = useState('');
  const [example, setExample] = useState<ExampleId | null>(null);
  const deferred = useDeferredValue(text);
  const ready = engine.status === 'ready' ? engine.engine : undefined;

  const analysis = useMemo(
    () => (ready && deferred.length > 0 ? analyzeText(ready.core, deferred, locale) : undefined),
    [ready, deferred, locale],
  );

  // Switching language re-renders the selected example in that language.
  useEffect(() => {
    if (ready && example) setText(buildExample(example, locale, ready.wordlist));
  }, [locale, ready, example]);

  const pick = (id: ExampleId) => {
    if (!ready) return;
    setText(buildExample(id, locale, ready.wordlist));
    setExample(id);
  };

  return (
    <section id="playground" aria-labelledby={`${ids}-title`} className="scroll-mt-24">
      <h2 id={`${ids}-title`} className="sr-only">
        {t('ui-web-playground-title')}
      </h2>
      <div className="grid items-start gap-6 lg:grid-cols-[minmax(0,5fr)_minmax(0,7fr)]">
        <div className={`${CARD} p-5 shadow-sm sm:p-6 lg:sticky lg:top-24`}>
          <label htmlFor={`${ids}-input`} className="text-base font-semibold">
            {t('ui-web-input-label')}
          </label>
          <p id={`${ids}-hint`} className="mt-0.5 text-sm text-fg-muted">
            {t('ui-web-input-hint')}
          </p>
          <textarea
            id={`${ids}-input`}
            value={text}
            onChange={(e) => {
              setText(e.target.value);
              setExample(null);
            }}
            placeholder={t('ui-web-input-placeholder')}
            aria-describedby={`${ids}-hint`}
            rows={9}
            // Browser spell-checkers can send text to a server ("enhanced spell check").
            spellCheck={false}
            autoCapitalize="off"
            autoComplete="off"
            autoCorrect="off"
            data-gramm="false"
            data-testid="input"
            className="mt-4 block min-h-44 w-full resize-y rounded-l2 border border-border-default bg-bg-subtle p-3 font-mono text-sm leading-relaxed text-fg shadow-[inset_0_1px_2px_var(--gray-a3)] transition-colors placeholder:text-fg-subtle hover:border-gray-a7 focus-visible:border-gray-8 focus-visible:outline-2 focus-visible:outline-offset-0 focus-visible:outline-focus"
          />
          <div className="mt-2 flex min-h-9 flex-wrap items-center justify-between gap-2 text-xs text-fg-muted tabular-nums">
            <span>
              {t('ui-web-chars', { count: text.length })}
              {analysis && (
                <>
                  {' · '}
                  <span data-testid="elapsed">
                    {t('ui-web-elapsed', { ms: analysis.ms < 1 ? '<1' : Math.round(analysis.ms) })}
                  </span>
                </>
              )}
            </span>
            <button
              type="button"
              className={BUTTON}
              onClick={() => {
                setText('');
                setExample(null);
              }}
              aria-disabled={text.length === 0}
            >
              {t('ui-web-clear')}
            </button>
          </div>

          <h3 className="mt-6 border-t border-border-muted pt-5 text-sm font-semibold">
            {t('ui-web-examples-title')}
          </h3>
          <p className="mt-0.5 text-xs text-fg-muted">{t('ui-web-examples-note')}</p>
          <ul className="mt-3 flex flex-wrap gap-2">
            {EXAMPLE_IDS.map((id) => (
              <li key={id}>
                <button
                  type="button"
                  data-example={id}
                  onClick={() => pick(id)}
                  aria-pressed={example === id}
                  aria-disabled={!ready}
                  className="inline-flex min-h-9 items-center rounded-l2 border border-border-default bg-bg-default px-3 text-sm font-medium text-fg shadow-xs transition-colors motion-reduce:transition-none hover:bg-bg-subtle aria-disabled:cursor-wait aria-disabled:opacity-60 aria-pressed:border-transparent aria-pressed:bg-solid aria-pressed:text-solid-fg aria-pressed:shadow-none aria-pressed:hover:bg-solid-hover"
                >
                  {t(`ui-web-example-${id}`)}
                </button>
              </li>
            ))}
          </ul>
          {example && (
            <p
              className="mt-3 rounded-l2 border-l-2 border-gray-8 bg-bg-subtle px-3 py-2 text-sm text-fg-muted"
              data-testid="example-note"
            >
              {t(`ui-web-example-${example}-note`)}
            </p>
          )}
        </div>

        <div aria-busy={engine.status === 'loading'} className="min-h-[28rem]">
          <h3 className="sr-only">{t('ui-web-results-title')}</h3>
          {/* One short polite summary instead of re-reading every card on each keystroke. */}
          <p role="status" className="sr-only">
            {analysis
              ? `${t(`ui-comp-action-${analysis.report.action}`)}, ${t('ui-comp-risk-value', {
                  score: Math.round(analysis.report.command.risk_score),
                })}`
              : ''}
          </p>
          <Results engine={engine} analysis={analysis} t={t} />
        </div>
      </div>
    </section>
  );
}

interface ResultsProps {
  engine: EngineState;
  analysis: Analysis | undefined;
  t: Translate;
}

function Results({ engine, analysis, t }: ResultsProps) {
  if (engine.status === 'loading') return <Skeleton label={t('ui-web-loading')} />;
  if (engine.status === 'error') {
    return (
      <p
        role="alert"
        className="rounded-l3 border border-quarantine-line bg-quarantine-bg p-5 text-sm text-fg"
      >
        {t('ui-web-engine-error')}
      </p>
    );
  }
  if (!analysis) {
    return (
      <div
        className="grid min-h-[28rem] place-items-center rounded-l3 border border-dashed border-gray-a6 bg-bg-subtle/60 p-8 text-center"
        data-testid="empty"
      >
        <div className="max-w-sm">
          <p className="text-lg font-semibold">{t('ui-web-empty-title')}</p>
          <p className="mt-1 text-sm text-fg-muted">{t('ui-web-empty-body')}</p>
        </div>
      </div>
    );
  }
  const { report, masked } = analysis;
  return (
    <div className="grid gap-5" data-testid="results">
      <VerdictCard report={report} headingLevel={4} />
      {showOnion(report) && (
        <OnionTrace trace={report.command.trace} tone={report.action} headingLevel={4} />
      )}
      {report.secrets.length > 0 && (
        <>
          <SecretList secrets={report.secrets} headingLevel={4} />
          {masked !== undefined && <MaskedSection masked={masked} analysis={analysis} t={t} />}
        </>
      )}
    </div>
  );
}

function MaskedSection({
  masked,
  analysis,
  t,
}: {
  masked: string;
  analysis: Analysis;
  t: Translate;
}) {
  const [state, setState] = useState<'idle' | 'ok' | 'fail'>('idle');
  const last = useRef(masked);
  useEffect(() => {
    if (last.current !== masked) {
      last.current = masked;
      setState('idle');
    }
  }, [masked]);

  const copy = async () => {
    try {
      // Write-only: the page never reads the clipboard.
      await navigator.clipboard.writeText(masked);
      setState('ok');
    } catch {
      setState('fail');
    }
  };

  return (
    <div className="grid gap-2">
      <MaskPreview masked={masked} secrets={analysis.report.secrets} headingLevel={4} />
      <div className="flex flex-wrap items-center gap-3">
        <button type="button" onClick={copy} data-testid="copy-masked" className={button()}>
          <CopyIcon className="size-4" />
          {t('ui-web-copy-masked')}
        </button>
        <p role="status" className="text-sm text-fg-muted">
          {state === 'ok' ? t('ui-web-copied') : state === 'fail' ? t('ui-web-copy-failed') : ''}
        </p>
      </div>
    </div>
  );
}

/** Same footprint as the results, so nothing jumps when the engine arrives. */
function Skeleton({ label }: { label: string }) {
  return (
    <div className="grid gap-5" data-testid="skeleton">
      <div className={`${CARD} overflow-hidden`}>
        <div className="flex items-center gap-4 border-b border-line px-5 py-4">
          <div className="skeleton size-10 rounded-full" />
          <div className="flex-1 space-y-2">
            <div className="skeleton h-3 w-24 rounded" />
            <div className="skeleton h-5 w-40 rounded" />
          </div>
        </div>
        <div className="space-y-4 px-5 py-5">
          <p className="text-sm text-fg-muted">{label}</p>
          <div className="skeleton h-2.5 w-full rounded-full" />
          <div className="skeleton h-3 w-11/12 rounded" />
          <div className="skeleton h-3 w-9/12 rounded" />
          <div className="skeleton h-3 w-10/12 rounded" />
        </div>
      </div>
      <div className="skeleton h-40 rounded-card" />
    </div>
  );
}
