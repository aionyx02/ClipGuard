import { useId } from 'react';
import { useT } from '../i18n/LocaleProvider';
import type { SecretFinding } from '../report';
import { cx } from './icons';

export interface MaskPreviewProps {
  /** Output of `mask(text, report)` from `@paste-warden/core` — already masked. */
  masked: string;
  /** `report.secrets`; their masked values are highlighted inside `masked`. */
  secrets?: SecretFinding[];
  headingLevel?: 2 | 3 | 4;
  className?: string;
}

interface Segment {
  text: string;
  mark: boolean;
  /** UTF-16 offset of the segment in the masked text. */
  start: number;
}

/** Splits `text` so every occurrence of a masked value becomes its own highlighted segment. */
export function segmentMasked(text: string, maskedValues: string[]): Segment[] {
  const needles = [...new Set(maskedValues.filter((v) => v.length > 0))].sort(
    (a, b) => b.length - a.length,
  );
  const segments: Segment[] = [];
  let plain = '';
  let plainStart = 0;
  let i = 0;
  outer: while (i < text.length) {
    for (const needle of needles) {
      if (text.startsWith(needle, i)) {
        if (plain) segments.push({ text: plain, mark: false, start: plainStart });
        plain = '';
        segments.push({ text: needle, mark: true, start: i });
        i += needle.length;
        plainStart = i;
        continue outer;
      }
    }
    plain += text[i];
    i += 1;
  }
  if (plain) segments.push({ text: plain, mark: false, start: plainStart });
  return segments;
}

/** Shows what the other side would receive if the masked version is pasted. */
export function MaskPreview({
  masked,
  secrets = [],
  headingLevel = 2,
  className,
}: MaskPreviewProps) {
  const t = useT();
  const id = useId();
  const Heading = `h${headingLevel}` as const;
  const segments = segmentMasked(
    masked,
    secrets.map((s) => s.masked),
  );
  return (
    <section
      aria-labelledby={`${id}-title`}
      className={cx(
        'rounded-card border border-line bg-surface p-5 text-fg shadow-card',
        className,
      )}
    >
      <Heading id={`${id}-title`} className="text-lg font-semibold">
        {t('ui-comp-mask-title')}
      </Heading>
      <p className="mt-0.5 text-sm text-fg-muted">{t('ui-comp-mask-note')}</p>
      <pre className="mt-3 overflow-x-auto rounded-lg border border-line bg-surface-2 p-3 font-mono text-sm leading-relaxed whitespace-pre-wrap break-words">
        {segments.map((seg) =>
          seg.mark ? (
            <mark
              key={seg.start}
              className="rounded bg-brand-200 px-0.5 text-ink-900 dark:bg-brand-800 dark:text-brand-100"
            >
              {seg.text}
            </mark>
          ) : (
            <span key={seg.start}>{seg.text}</span>
          ),
        )}
      </pre>
    </section>
  );
}
