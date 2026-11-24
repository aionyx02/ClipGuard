import { ShieldMark, useLocale } from '@paste-warden/ui';
import { useCallback, useEffect, useState } from 'react';
import { browser } from 'wxt/browser';
import type { TabStatus, ToContent } from '../../lib/messages';
import { type BlockRecord, isAllowlisted, isBlockRecord, RECENT_KEY } from '../../lib/settings';
import { Switch } from '../../ui/Switch';
import { useSettings } from '../../ui/settings-store';

type Status = TabStatus | 'unavailable' | 'loading';

async function activeTabStatus(): Promise<Status> {
  try {
    const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
    if (tab?.id === undefined) return 'unavailable';
    const msg: ToContent = { type: 'status' };
    const status = (await browser.tabs.sendMessage(tab.id, msg, { frameId: 0 })) as
      | TabStatus
      | undefined;
    return status && typeof status.host === 'string' ? status : 'unavailable';
  } catch {
    // No content script there: browser pages, the extension stores, or a tab opened before install.
    return 'unavailable';
  }
}

function useRecent(): [BlockRecord[], () => void] {
  const [recent, setRecent] = useState<BlockRecord[]>([]);
  useEffect(() => {
    const read = (v: unknown) => setRecent(Array.isArray(v) ? v.filter(isBlockRecord) : []);
    browser.storage.local.get(RECENT_KEY).then((got) => read(got[RECENT_KEY]));
    const listener = (changes: Record<string, { newValue?: unknown }>, area: string) => {
      if (area === 'local' && changes[RECENT_KEY]) read(changes[RECENT_KEY].newValue);
    };
    browser.storage.onChanged.addListener(listener);
    return () => browser.storage.onChanged.removeListener(listener);
  }, []);
  const clear = useCallback(() => {
    void browser.storage.local.set({ [RECENT_KEY]: [] });
  }, []);
  return [recent, clear];
}

const KIND_TONE: Record<BlockRecord['kind'], string> = {
  command: 'bg-quarantine-bg text-quarantine border-quarantine-line',
  warning: 'bg-warn-bg text-warn border-warn-line',
  pastejack: 'bg-warn-bg text-warn border-warn-line',
  secret: 'bg-allow-bg text-allow border-allow-line',
};

export function App() {
  const { t, locale } = useLocale();
  const { settings, update } = useSettings();
  const [status, setStatus] = useState<Status>('loading');
  const [recent, clearRecent] = useRecent();

  useEffect(() => {
    void activeTabStatus().then(setStatus);
  }, []);

  const host = typeof status === 'object' ? status.host : '';
  const paused = host !== '' && isAllowlisted(host, settings.allowlist);
  const time = new Intl.DateTimeFormat(locale, { dateStyle: 'short', timeStyle: 'short' });

  let headline: string;
  let tone: string;
  if (status === 'unavailable') {
    headline = t('ui-ext-popup-status-unavailable');
    tone = 'border-line bg-surface-2 text-fg-muted';
  } else if (!settings.enabled) {
    headline = t('ui-ext-popup-status-off');
    tone = 'border-warn-line bg-warn-bg text-warn';
  } else if (paused) {
    headline = t('ui-ext-popup-status-paused', { host });
    tone = 'border-warn-line bg-warn-bg text-warn';
  } else {
    headline = t('ui-ext-popup-status-on');
    tone = 'border-allow-line bg-allow-bg text-allow';
  }

  const togglePause = (on: boolean) => {
    if (!host) return;
    const rest = settings.allowlist.filter((h) => h !== host && !isAllowlisted(host, [h]));
    update({ allowlist: on ? [...rest, host] : rest });
  };

  return (
    <div className="w-[360px] bg-canvas p-4 text-fg">
      <header className="flex items-center gap-2.5">
        <ShieldMark className="size-8" />
        <h1 className="text-base font-bold tracking-tight">
          Paste<span className="text-accent">Warden</span>
        </h1>
      </header>

      <section
        aria-live="polite"
        className={`mt-3 rounded-[var(--radius-card)] border px-3 py-2.5 text-sm ${tone}`}
      >
        <p className="font-medium">{status === 'loading' ? '…' : headline}</p>
        {typeof status === 'object' ? (
          <p className="mt-1 text-xs opacity-90">
            {t('ui-ext-popup-page-stats', { blocked: status.blocked, warned: status.warned })}
            {status.backend ? ` · ${t('ui-ext-popup-engine', { backend: status.backend })}` : ''}
          </p>
        ) : null}
      </section>

      <section className="mt-3 divide-y divide-line rounded-[var(--radius-card)] border border-line bg-surface px-3">
        <Switch
          label={t('ui-ext-popup-toggle-enabled')}
          checked={settings.enabled}
          onChange={(enabled) => update({ enabled })}
        />
        <Switch
          label={t('ui-ext-popup-toggle-site')}
          description={host || undefined}
          checked={paused}
          disabled={!host || !settings.enabled}
          onChange={togglePause}
        />
      </section>

      <section className="mt-3 rounded-[var(--radius-card)] border border-line bg-surface p-3">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold">{t('ui-ext-popup-recent')}</h2>
          {recent.length > 0 ? (
            <button
              type="button"
              onClick={clearRecent}
              className="rounded-md px-2 py-0.5 text-xs text-fg-muted hover:bg-surface-2"
            >
              {t('ui-ext-popup-clear')}
            </button>
          ) : null}
        </div>
        {recent.length === 0 ? (
          <p className="mt-2 text-xs text-fg-muted">{t('ui-ext-popup-recent-empty')}</p>
        ) : (
          <ul className="mt-2 max-h-56 space-y-1.5 overflow-y-auto">
            {recent.map((r) => (
              <li
                key={`${r.time}-${r.domain}-${r.kind}`}
                className="rounded-lg bg-surface-2 px-2.5 py-1.5 text-xs"
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="truncate font-medium" title={r.domain}>
                    {r.domain || '—'}
                  </span>
                  <time
                    className="shrink-0 text-fg-muted"
                    dateTime={new Date(r.time).toISOString()}
                  >
                    {time.format(r.time)}
                  </time>
                </div>
                <div className="mt-1 flex items-center gap-2">
                  <span className={`rounded border px-1.5 py-px text-[11px] ${KIND_TONE[r.kind]}`}>
                    {t(`ui-ext-kind-${r.kind}`)}
                  </span>
                  {r.masked ? (
                    <code className="truncate font-mono text-[11px] text-fg-muted">{r.masked}</code>
                  ) : null}
                </div>
              </li>
            ))}
          </ul>
        )}
        <p className="mt-2 text-[11px] leading-snug text-fg-muted">
          {t('ui-ext-popup-recent-note')}
        </p>
      </section>

      <footer className="mt-3 flex justify-end">
        <button
          type="button"
          onClick={() => void browser.runtime.openOptionsPage()}
          className="rounded-lg border border-line bg-surface px-3 py-1.5 text-sm font-medium hover:bg-surface-2"
        >
          {t('ui-ext-popup-settings')}
        </button>
      </footer>
    </div>
  );
}
