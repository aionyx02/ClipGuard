import { useId } from 'react';
import { type LocaleMode, useLocale } from '../i18n/LocaleProvider';
import { type ThemeMode, useTheme } from '../theme/ThemeProvider';
import { cx } from './icons';

interface SegmentedProps<T extends string> {
  legend: string;
  value: T;
  options: Array<{ value: T; label: string; lang?: string }>;
  onChange: (value: T) => void;
  className?: string;
}

/** A radio group styled as a segmented control (native radios: arrow keys work for free). */
function Segmented<T extends string>({
  legend,
  value,
  options,
  onChange,
  className,
}: SegmentedProps<T>) {
  const name = useId();
  return (
    <fieldset className={cx('min-w-0', className)}>
      <legend className="mb-1.5 text-xs font-medium text-fg-muted">{legend}</legend>
      <div className="inline-flex rounded-lg border border-line bg-surface-2 p-0.5">
        {options.map((o) => (
          <label
            key={o.value}
            lang={o.lang}
            className="relative cursor-pointer rounded-md px-3 py-1 text-sm text-fg-muted has-checked:bg-surface has-checked:font-medium has-checked:text-fg has-checked:shadow-sm has-focus-visible:outline-2 has-focus-visible:outline-focus"
          >
            <input
              type="radio"
              name={name}
              value={o.value}
              checked={value === o.value}
              onChange={() => onChange(o.value)}
              className="sr-only"
            />
            {o.label}
          </label>
        ))}
      </div>
    </fieldset>
  );
}

export function ThemeSwitcher({ className }: { className?: string }) {
  const { mode, setMode } = useTheme();
  const { t } = useLocale();
  const modes: ThemeMode[] = ['system', 'light', 'dark'];
  return (
    <Segmented
      className={className}
      legend={t('ui-comp-pref-theme')}
      value={mode}
      onChange={setMode}
      options={modes.map((m) => ({ value: m, label: t(`ui-comp-pref-theme-${m}`) }))}
    />
  );
}

export function LocaleSwitcher({ className }: { className?: string }) {
  const { mode, setMode, t } = useLocale();
  const modes: LocaleMode[] = ['system', 'zh-TW', 'en'];
  return (
    <Segmented
      className={className}
      legend={t('ui-comp-pref-language')}
      value={mode}
      onChange={setMode}
      options={modes.map((m) => ({
        value: m,
        label: t(`ui-comp-pref-language-${m}`),
        lang: m === 'system' ? undefined : m,
      }))}
    />
  );
}
