import { useId } from 'react';
import { useT } from '../i18n/LocaleProvider';
import type { SecretFinding } from '../report';
import { cx } from './icons';

export interface SecretListProps {
  /** From `report.secrets` — masked values only; this component never sees plaintext. */
  secrets: SecretFinding[];
  headingLevel?: 2 | 3 | 4;
  className?: string;
}

export function SecretList({ secrets, headingLevel = 2, className }: SecretListProps) {
  const t = useT();
  const id = useId();
  const Heading = `h${headingLevel}` as const;
  return (
    <section
      aria-labelledby={`${id}-title`}
      className={cx(
        'rounded-card border border-line bg-surface p-5 text-fg shadow-card',
        className,
      )}
    >
      <Heading id={`${id}-title`} className="flex items-center gap-2 text-lg font-semibold">
        <KeyGlyph className="size-5 text-accent" />
        {t('ui-comp-secrets-title')}
        {secrets.length > 0 && (
          <span className="rounded-full bg-quarantine-bg px-2 py-px text-xs font-semibold text-quarantine tabular-nums">
            {secrets.length}
          </span>
        )}
      </Heading>
      {secrets.length === 0 ? (
        <p className="mt-2 text-sm text-fg-muted">{t('ui-comp-secrets-empty')}</p>
      ) : (
        <>
          <p className="mt-0.5 text-sm text-fg-muted">{t('ui-comp-secrets-note')}</p>
          <ul className="mt-3 divide-y divide-line overflow-hidden rounded-lg border border-line">
            {secrets.map((s) => (
              <li
                key={`${s.rule_id}:${s.span_utf16[0]}`}
                data-kind={s.kind}
                className="flex flex-wrap items-center justify-between gap-x-4 gap-y-1 bg-surface-2/50 px-3 py-2.5"
              >
                <div className="min-w-0">
                  <p className="text-sm font-medium">{s.label}</p>
                  <p className="text-xs text-fg-muted">
                    {t('ui-comp-secrets-rule')}: <code className="font-mono">{s.rule_id}</code>
                  </p>
                </div>
                <code className="rounded-md bg-ink-900 px-2 py-1 dark:bg-ink-950 font-mono text-sm tracking-wide text-brand-200">
                  {s.masked}
                </code>
              </li>
            ))}
          </ul>
        </>
      )}
    </section>
  );
}

function KeyGlyph({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 24 24"
      className={className}
      aria-hidden="true"
      focusable="false"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <circle cx="8" cy="15" r="4" />
      <path d="m11 12 9-9M17 6l3 3M14.5 8.5l2 2" />
    </svg>
  );
}
