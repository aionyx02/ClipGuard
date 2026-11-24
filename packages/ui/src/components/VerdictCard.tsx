import { useId } from 'react';
import { useT } from '../i18n/LocaleProvider';
import type { Action, CommandLevel, Report } from '../report';
import { ActionIcon, cx, TONE } from './icons';

const LEVEL_TONE: Record<CommandLevel, Action> = {
  none: 'allow',
  suspicious: 'warn',
  malicious: 'quarantine',
};

export interface VerdictCardProps {
  report: Report;
  /** Heading level for the card title (default 2). */
  headingLevel?: 2 | 3 | 4;
  className?: string;
}

/** Action, command level, risk score and the reasons behind them. */
export function VerdictCard({ report, headingLevel = 2, className }: VerdictCardProps) {
  const t = useT();
  const id = useId();
  const { action, command, hidden } = report;
  const tone = TONE[action];
  const levelTone = TONE[LEVEL_TONE[command.level]];
  const score = Math.max(0, Math.min(100, Math.round(command.risk_score)));
  const Heading = `h${headingLevel}` as const;
  const SubHeading = `h${headingLevel + 1}` as 'h3' | 'h4' | 'h5';

  return (
    <section
      aria-labelledby={`${id}-title`}
      data-action={action}
      className={cx(
        'relative overflow-hidden rounded-card border bg-surface text-fg shadow-card',
        tone.border,
        className,
      )}
    >
      <div aria-hidden="true" className={cx('absolute inset-y-0 left-0 w-1.5', tone.fill)} />
      <div className={cx('flex items-start gap-4 border-b px-5 py-4 pl-6', tone.bg, tone.border)}>
        <span
          className={cx(
            'mt-0.5 inline-flex size-10 shrink-0 items-center justify-center rounded-full bg-surface ring-1',
            tone.text,
            tone.ring,
          )}
        >
          <ActionIcon action={action} className="size-6" />
        </span>
        <div className="min-w-0 flex-1">
          <p className="text-xs font-medium tracking-wide text-fg-muted uppercase">
            {t('ui-comp-verdict-title')}
          </p>
          <Heading id={`${id}-title`} className={cx('text-xl font-semibold', tone.text)}>
            {t(`ui-comp-action-${action}`)}
          </Heading>
          <p className="mt-0.5 text-sm text-fg">{t(`ui-comp-action-${action}-desc`)}</p>
        </div>
        <div className="shrink-0 text-right">
          <p className="text-xs text-fg-muted">{t('ui-comp-level-label')}</p>
          <span
            className={cx(
              'mt-1 inline-flex items-center rounded-full border px-2.5 py-0.5 text-sm font-medium',
              levelTone.text,
              levelTone.border,
              'bg-surface',
            )}
          >
            {t(`ui-comp-level-${command.level}`)}
          </span>
        </div>
      </div>

      <div className="space-y-5 px-5 py-4 pl-6">
        <div>
          <div className="flex items-baseline justify-between">
            <span id={`${id}-risk`} className="text-sm font-medium text-fg">
              {t('ui-comp-risk-label')}
            </span>
            <span className={cx('font-mono text-sm font-semibold tabular-nums', tone.text)}>
              {t('ui-comp-risk-value', { score })}
            </span>
          </div>
          {/* biome-ignore lint/a11y/useSemanticElements: <meter> cannot be styled consistently across browsers */}
          <div
            role="meter"
            aria-labelledby={`${id}-risk`}
            aria-valuemin={0}
            aria-valuemax={100}
            aria-valuenow={score}
            aria-valuetext={t('ui-comp-risk-value', { score })}
            className="mt-2 h-2.5 overflow-hidden rounded-full bg-surface-2 ring-1 ring-line ring-inset"
          >
            <div
              className={cx('h-full rounded-full transition-[width] duration-500', tone.fill)}
              style={{ width: `${score}%` }}
            />
          </div>
        </div>

        <div>
          <SubHeading className="text-sm font-semibold text-fg">
            {t('ui-comp-reasons-title')}
          </SubHeading>
          {command.reasons.length === 0 && hidden.reasons.length === 0 ? (
            <p className="mt-1 text-sm text-fg-muted">{t('ui-comp-reasons-empty')}</p>
          ) : (
            <ul className="mt-2 space-y-1.5">
              {command.reasons.map((r) => (
                <li
                  key={`${r.id}:${r.text}`}
                  data-reason={r.id}
                  className="flex gap-2 text-sm leading-relaxed"
                >
                  <span
                    aria-hidden="true"
                    className={cx('mt-2 size-1.5 shrink-0 rounded-full', tone.fill)}
                  />
                  <span>{r.text}</span>
                </li>
              ))}
            </ul>
          )}
        </div>

        {hidden.reasons.length > 0 && (
          <div>
            <SubHeading className="text-sm font-semibold text-fg">
              {t('ui-comp-hidden-title')}
            </SubHeading>
            <ul className="mt-2 space-y-1.5">
              {hidden.reasons.map((r) => (
                <li
                  key={`${r.id}:${r.text}`}
                  data-reason={r.id}
                  className="flex gap-2 text-sm leading-relaxed"
                >
                  <span
                    aria-hidden="true"
                    className="mt-2 size-1.5 shrink-0 rounded-full bg-warn"
                  />
                  <span>{r.text}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        {command.hosts.length > 0 && (
          <div>
            <SubHeading className="text-sm font-semibold text-fg">
              {t('ui-comp-hosts-title')}
            </SubHeading>
            <ul className="mt-2 flex flex-wrap gap-2">
              {command.hosts.map((h) => (
                <li
                  key={h}
                  className="rounded-md border border-line bg-surface-2 px-2 py-0.5 font-mono text-xs"
                >
                  {h}
                </li>
              ))}
            </ul>
          </div>
        )}

        {report.wallets.length > 0 && (
          <p className="text-sm text-fg-muted">
            {t('ui-comp-wallets', { count: report.wallets.length })}
          </p>
        )}

        {report.truncated && (
          <p className="rounded-md border border-warn-line bg-warn-bg px-3 py-2 text-sm text-fg">
            {t('ui-comp-truncated')}
          </p>
        )}
      </div>
    </section>
  );
}
