import { useT } from '@paste-warden/ui';
import { type FormEvent, useId, useState } from 'react';
import { type CommandError, ipc, toCommandError } from '../lib/ipc';
import { Button, Switch } from '../ui/controls';
import { useSettings } from '../ui/DesktopRoot';
import { ErrorText } from './ErrorText';

export function PasteGuardSwitches() {
  const t = useT();
  const { settings, patch } = useSettings();
  const { registered, detected } = settings.pasteGuard;
  const platform = settings.platform;
  const set = (next: { registered: boolean; detected: boolean }) => {
    patch({ pasteGuard: { ...settings.pasteGuard, ...next } });
    ipc.setPasteGuard(next.registered, next.detected).catch(() => {});
  };
  return (
    <>
      <p className="rounded-lg border border-warn-line bg-warn-bg px-3 py-2 text-xs leading-relaxed text-warn">
        {t('ui-desktop-paste-guard-keyboard-only', { platform })}
      </p>
      <div className="divide-y divide-line">
        <Switch
          label={t('ui-desktop-paste-guard-registered')}
          description={t('ui-desktop-paste-guard-registered-desc')}
          checked={registered}
          onChange={(v) => set({ registered: v, detected })}
        />
        <Switch
          label={t('ui-desktop-paste-guard-detected')}
          description={t('ui-desktop-paste-guard-detected-desc')}
          checked={detected}
          onChange={(v) => set({ registered, detected: v })}
        />
      </div>
    </>
  );
}

export function Allowlist() {
  const t = useT();
  const { settings, patch } = useSettings();
  const [value, setValue] = useState('');
  const [error, setError] = useState<CommandError | null>(null);
  const [busy, setBusy] = useState(false);
  const inputId = useId();
  const allowlist = settings.pasteGuard.allowlist;

  const add = async (e: FormEvent) => {
    e.preventDefault();
    const name = value.trim();
    if (!name) {
      setError({ messageId: 'ui-desktop-allowlist-empty-name' });
      return;
    }
    setBusy(true);
    try {
      await ipc.allowlistAdd(name);
      if (!allowlist.includes(name)) {
        patch({ pasteGuard: { ...settings.pasteGuard, allowlist: [...allowlist, name] } });
      }
      setValue('');
      setError(null);
    } catch (err) {
      setError(toCommandError(err));
    } finally {
      setBusy(false);
    }
  };

  const remove = (name: string) => {
    patch({
      pasteGuard: { ...settings.pasteGuard, allowlist: allowlist.filter((n) => n !== name) },
    });
    ipc.allowlistRemove(name).catch(() => {});
  };

  return (
    <>
      <form onSubmit={add} className="flex flex-wrap items-end gap-2">
        <div className="min-w-0 flex-1">
          <label htmlFor={inputId} className="mb-1 block text-xs font-medium text-fg-muted">
            {t('ui-desktop-allowlist-label')}
          </label>
          <input
            id={inputId}
            value={value}
            onChange={(e) => {
              setValue(e.target.value);
              setError(null);
            }}
            placeholder={t('ui-desktop-allowlist-placeholder', { platform: settings.platform })}
            aria-invalid={error !== null}
            aria-describedby={error ? `${inputId}-e` : undefined}
            autoComplete="off"
            spellCheck={false}
            className="w-full rounded-lg border border-line bg-surface-2 px-3 py-1.5 font-mono text-sm"
          />
        </div>
        <Button type="submit" variant="primary" disabled={busy}>
          {t('ui-desktop-allowlist-add')}
        </Button>
      </form>
      <ErrorText id={`${inputId}-e`} error={error} />
      {allowlist.length === 0 ? (
        <p className="mt-3 text-sm text-fg-muted">{t('ui-desktop-allowlist-none')}</p>
      ) : (
        <ul className="mt-3 divide-y divide-line rounded-lg border border-line">
          {allowlist.map((name) => (
            <li key={name} className="flex items-center justify-between gap-2 px-3 py-1.5">
              <code className="truncate font-mono text-sm">{name}</code>
              <button
                type="button"
                aria-label={t('ui-desktop-allowlist-remove', { name })}
                onClick={() => remove(name)}
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
