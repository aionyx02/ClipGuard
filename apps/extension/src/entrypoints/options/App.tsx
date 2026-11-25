import { LocaleSwitcher, ShieldMark, ThemeSwitcher, useLocale } from '@paste-warden/ui';
import { type FormEvent, type ReactNode, useEffect, useId, useState } from 'react';
import { browser } from 'wxt/browser';
import type { ToBackground } from '../../lib/messages';
import { type DesktopState, INITIAL_RECORD, normalizeRecord } from '../../lib/native';
import {
  type ExtSettings,
  effectivePacks,
  normalizeHost,
  PACKS,
  type Pack,
} from '../../lib/settings';
import { Switch } from '../../ui/Switch';
import { useSettings } from '../../ui/settings-store';

function Section({
  title,
  description,
  children,
}: {
  title: string;
  description?: string;
  children: ReactNode;
}) {
  const id = useId();
  return (
    <section
      aria-labelledby={id}
      className="rounded-[var(--radius-card)] border border-line bg-surface p-5 shadow-[var(--shadow-card)]"
    >
      <h2 id={id} className="text-base font-semibold">
        {title}
      </h2>
      {description ? <p className="mt-1 text-sm text-fg-muted">{description}</p> : null}
      <div className="mt-3">{children}</div>
    </section>
  );
}

type BoolKey = {
  [K in keyof ExtSettings]: ExtSettings[K] extends boolean ? K : never;
}[keyof ExtSettings];

function Toggle({ k, id, disabled }: { k: BoolKey; id: string; disabled?: boolean }) {
  const { t } = useLocale();
  const { settings, update } = useSettings();
  return (
    <Switch
      label={t(`ui-ext-opt-${id}`)}
      description={t(`ui-ext-opt-${id}-desc`)}
      checked={settings[k]}
      disabled={disabled}
      onChange={(v) => update({ [k]: v } as Partial<ExtSettings>)}
    />
  );
}

function Packs() {
  const { t } = useLocale();
  const { settings, update } = useSettings();
  const auto = settings.packs === null;
  const active = effectivePacks(settings, navigator.languages);
  const toggle = (pack: Pack, on: boolean) => {
    const set = new Set(active);
    if (on) set.add(pack);
    else set.delete(pack);
    update({ packs: PACKS.filter((p) => set.has(p)) });
  };
  return (
    <>
      <Switch
        label={t('ui-ext-opt-packs-auto')}
        description={navigator.languages.join(', ')}
        checked={auto}
        onChange={(on) => update({ packs: on ? null : active })}
      />
      <fieldset className="mt-2 grid grid-cols-2 gap-2 sm:grid-cols-4" disabled={auto}>
        <legend className="sr-only">{t('ui-ext-options-packs')}</legend>
        {PACKS.map((pack) => (
          <label
            key={pack}
            className="flex cursor-pointer items-center gap-2 rounded-lg border border-line bg-surface-2 px-3 py-2 text-sm has-disabled:cursor-default has-disabled:opacity-60"
          >
            <input
              type="checkbox"
              className="size-4 accent-[var(--pw-accent)]"
              checked={active.includes(pack)}
              disabled={auto || pack === 'universal'}
              onChange={(e) => toggle(pack, e.target.checked)}
            />
            {t(`ui-ext-pack-${pack}`)}
          </label>
        ))}
      </fieldset>
    </>
  );
}

function Allowlist() {
  const { t } = useLocale();
  const { settings, update } = useSettings();
  const [value, setValue] = useState('');
  const [error, setError] = useState(false);
  const inputId = useId();
  const add = (e: FormEvent) => {
    e.preventDefault();
    const host = normalizeHost(value);
    if (!host) {
      setError(true);
      return;
    }
    update({ allowlist: [...settings.allowlist.filter((h) => h !== host), host] });
    setValue('');
    setError(false);
  };
  return (
    <>
      <form onSubmit={add} className="flex flex-wrap items-end gap-2">
        <div className="min-w-0 flex-1">
          <label htmlFor={inputId} className="mb-1 block text-xs font-medium text-fg-muted">
            {t('ui-ext-allowlist-label')}
          </label>
          <input
            id={inputId}
            value={value}
            onChange={(e) => {
              setValue(e.target.value);
              setError(false);
            }}
            placeholder={t('ui-ext-allowlist-placeholder')}
            aria-invalid={error}
            aria-describedby={error ? `${inputId}-e` : undefined}
            autoComplete="off"
            spellCheck={false}
            className="w-full rounded-lg border border-line bg-surface-2 px-3 py-1.5 font-mono text-sm"
          />
        </div>
        <button
          type="submit"
          className="rounded-lg bg-accent px-4 py-1.5 text-sm font-semibold text-accent-fg"
        >
          {t('ui-ext-allowlist-add')}
        </button>
      </form>
      {error ? (
        <p id={`${inputId}-e`} role="alert" className="mt-1.5 text-xs text-quarantine">
          {t('ui-ext-allowlist-invalid')}
        </p>
      ) : null}
      {settings.allowlist.length === 0 ? (
        <p className="mt-3 text-sm text-fg-muted">{t('ui-ext-allowlist-empty')}</p>
      ) : (
        <ul className="mt-3 divide-y divide-line rounded-lg border border-line">
          {settings.allowlist.map((host) => (
            <li key={host} className="flex items-center justify-between gap-2 px-3 py-1.5">
              <code className="truncate font-mono text-sm">{host}</code>
              <button
                type="button"
                aria-label={t('ui-ext-allowlist-remove', { host })}
                onClick={() => update({ allowlist: settings.allowlist.filter((h) => h !== host) })}
                className="rounded-md px-2 py-0.5 text-lg leading-none text-fg-muted hover:bg-surface-2"
              >
                ×
              </button>
            </li>
          ))}
        </ul>
      )}
    </>
  );
}

const askBackground = async (msg: ToBackground) =>
  normalizeRecord(await browser.runtime.sendMessage(msg).catch(() => INITIAL_RECORD));

const STATE_ID: Record<DesktopState, string> = {
  off: 'ui-ext-desktop-state-off',
  absent: 'ui-ext-desktop-state-absent',
  not_running: 'ui-ext-desktop-state-not-running',
  incompatible: 'ui-ext-desktop-state-incompatible',
  running: 'ui-ext-desktop-state-running',
};

/** Optional link to the desktop app: the permission is requested only from this button. */
function DesktopLink() {
  const { t } = useLocale();
  const [state, setState] = useState<DesktopState | null>(null);
  const [denied, setDenied] = useState(false);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    void askBackground({ type: 'native-status' }).then((r) => setState(r.state));
  }, []);
  const run = async (fn: () => Promise<void>) => {
    setBusy(true);
    try {
      await fn();
    } finally {
      setBusy(false);
    }
  };
  const connect = () =>
    run(async () => {
      // Must run straight from the click (user gesture).
      const granted = await browser.permissions
        .request({ permissions: ['nativeMessaging'] })
        .catch(() => false);
      setDenied(!granted);
      if (granted) setState((await askBackground({ type: 'native-probe' })).state);
    });
  const disconnect = () =>
    run(async () => {
      await browser.permissions.remove({ permissions: ['nativeMessaging'] }).catch(() => false);
      setState((await askBackground({ type: 'native-probe' })).state);
    });
  const check = () =>
    run(async () => setState((await askBackground({ type: 'native-probe' })).state));
  const button =
    'rounded-lg px-4 py-1.5 text-sm font-semibold disabled:cursor-default disabled:opacity-60';
  return (
    <>
      <p role="status" aria-live="polite" className="text-sm">
        {state ? t(STATE_ID[state]) : '…'}
      </p>
      {denied ? (
        <p role="alert" className="mt-1.5 text-xs text-fg-muted">
          {t('ui-ext-desktop-denied')}
        </p>
      ) : null}
      <div className="mt-3 flex flex-wrap gap-2">
        {state === 'off' || state === null ? (
          <button
            type="button"
            disabled={busy || state === null}
            onClick={connect}
            className={`${button} bg-accent text-accent-fg`}
          >
            {t('ui-ext-desktop-connect')}
          </button>
        ) : (
          <>
            <button
              type="button"
              disabled={busy}
              onClick={check}
              className={`${button} border border-line bg-surface-2`}
            >
              {t('ui-ext-desktop-check')}
            </button>
            <button
              type="button"
              disabled={busy}
              onClick={disconnect}
              className={`${button} border border-line bg-surface-2`}
            >
              {t('ui-ext-desktop-disconnect')}
            </button>
          </>
        )}
      </div>
    </>
  );
}

export function App() {
  const { t } = useLocale();
  const { settings } = useSettings();
  const off = !settings.enabled;
  return (
    <div className="min-h-screen bg-canvas text-fg">
      <div className="mx-auto max-w-2xl px-4 py-8 sm:px-6">
        <header className="flex items-center gap-3">
          <ShieldMark className="size-10" />
          <div>
            <h1 className="text-xl font-bold tracking-tight">{t('ui-ext-options-title')}</h1>
            <p className="text-sm text-fg-muted">{t('ui-ext-options-privacy')}</p>
          </div>
        </header>
        <main className="mt-6 grid gap-5">
          <Section title={t('ui-ext-options-protection')}>
            <div className="divide-y divide-line">
              <Toggle k="enabled" id="enabled" />
              <Toggle k="guardWrites" id="guard-writes" disabled={off} />
              <Toggle k="guardPaste" id="guard-paste" disabled={off} />
              <Toggle k="pastejack" id="pastejack" disabled={off} />
            </div>
          </Section>
          <Section title={t('ui-ext-options-strictness')}>
            <div className="divide-y divide-line">
              <Toggle k="block_malicious_commands" id="block-malicious" disabled={off} />
              <Toggle k="warn_suspicious_commands" id="warn-suspicious" disabled={off} />
              <Toggle k="detect_secrets" id="detect-secrets" disabled={off} />
              <Toggle k="detect_hidden_chars" id="detect-hidden" disabled={off} />
            </div>
          </Section>
          <Section title={t('ui-ext-options-packs')} description={t('ui-ext-options-packs-desc')}>
            <Packs />
          </Section>
          <Section
            title={t('ui-ext-options-appearance')}
            description={t('ui-ext-options-appearance-desc')}
          >
            <div className="flex flex-wrap gap-6">
              <LocaleSwitcher />
              <ThemeSwitcher />
            </div>
          </Section>
          <Section
            title={t('ui-ext-options-allowlist')}
            description={t('ui-ext-options-allowlist-desc')}
          >
            <Allowlist />
          </Section>
          <Section
            title={t('ui-ext-options-desktop')}
            description={t('ui-ext-options-desktop-desc')}
          >
            <DesktopLink />
          </Section>
        </main>
      </div>
    </div>
  );
}
