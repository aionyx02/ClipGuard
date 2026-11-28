// Registered secrets (§4.7, detection-rules.md §5.1). The secret is typed into uncontrolled
// password inputs: it never lives in React state, is read once on submit, and both inputs are
// emptied right away, whether Rust accepts it or not. The list shows label, length and date only.
import { useLocale, useT } from '@paste-warden/ui';
import { type FormEvent, useCallback, useEffect, useId, useRef, useState } from 'react';
import { type CommandError, ipc, type RegisteredSecret, toCommandError } from '../lib/ipc';
import { Button } from '../ui/controls';

type Field = 'secret' | 'confirm' | 'label';

const INPUT =
  'w-full rounded-lg border border-line bg-surface-2 px-3 py-1.5 text-sm aria-[invalid=true]:border-quarantine';

export function RegisterSecretForm({ onRegistered }: { onRegistered: () => void }) {
  const t = useT();
  const id = useId();
  const secretRef = useRef<HTMLInputElement>(null);
  const confirmRef = useRef<HTMLInputElement>(null);
  const labelRef = useRef<HTMLInputElement>(null);
  const [error, setError] = useState<CommandError | null>(null);
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const secretEl = secretRef.current;
    const confirmEl = confirmRef.current;
    const labelEl = labelRef.current;
    if (!secretEl || !confirmEl || !labelEl) return;
    const secret = secretEl.value;
    const confirm = confirmEl.value;
    // Clear before the round trip so the secret is gone from the DOM even if Rust never answers.
    secretEl.value = '';
    confirmEl.value = '';
    setBusy(true);
    setDone(false);
    try {
      await ipc.registerSecret(secret, confirm, labelEl.value);
      labelEl.value = '';
      setError(null);
      setDone(true);
      onRegistered();
    } catch (err) {
      const next = toCommandError(err);
      setError(next);
      (next.field === 'label' ? labelEl : secretEl).focus();
    } finally {
      setBusy(false);
    }
  };

  const errorFor = (field: Field | null) =>
    error && (error.field ?? null) === field ? error : null;
  const describe = (field: Field) => (errorFor(field) ? `${id}-${field}-e` : undefined);

  const fieldError = (field: Field | null) => {
    const e = errorFor(field);
    return e ? (
      <p id={`${id}-${field ?? 'form'}-e`} role="alert" className="mt-1 text-xs text-quarantine">
        {t(e.messageId, e.args)}
      </p>
    ) : null;
  };

  return (
    <form onSubmit={submit} className="grid gap-3" autoComplete="off" noValidate>
      <div>
        <label htmlFor={`${id}-secret`} className="mb-1 block text-xs font-medium text-fg-muted">
          {t('ui-desktop-secrets-secret')}
        </label>
        <input
          ref={secretRef}
          id={`${id}-secret`}
          type="password"
          autoComplete="new-password"
          spellCheck={false}
          aria-invalid={errorFor('secret') !== null}
          aria-describedby={describe('secret')}
          className={`${INPUT} font-mono`}
        />
        {fieldError('secret')}
      </div>
      <div>
        <label htmlFor={`${id}-confirm`} className="mb-1 block text-xs font-medium text-fg-muted">
          {t('ui-desktop-secrets-confirm')}
        </label>
        <input
          ref={confirmRef}
          id={`${id}-confirm`}
          type="password"
          autoComplete="new-password"
          spellCheck={false}
          aria-invalid={errorFor('confirm') !== null}
          aria-describedby={describe('confirm')}
          className={`${INPUT} font-mono`}
        />
        {fieldError('confirm')}
      </div>
      <div>
        <label htmlFor={`${id}-label`} className="mb-1 block text-xs font-medium text-fg-muted">
          {t('ui-desktop-secrets-label')}
        </label>
        <input
          ref={labelRef}
          id={`${id}-label`}
          type="text"
          placeholder={t('ui-desktop-secrets-label-placeholder')}
          aria-invalid={errorFor('label') !== null}
          aria-describedby={describe('label')}
          className={INPUT}
        />
        {fieldError('label')}
      </div>
      {fieldError(null)}
      <div className="flex items-center gap-3">
        <Button type="submit" variant="primary" disabled={busy}>
          {t('ui-desktop-secrets-add')}
        </Button>
        {done ? (
          <span role="status" className="text-xs text-allow">
            {t('ui-desktop-secrets-added')}
          </span>
        ) : null}
      </div>
      <p className="text-xs leading-relaxed text-fg-muted">{t('ui-desktop-secrets-privacy')}</p>
    </form>
  );
}

function SecretRow({ secret, onRemoved }: { secret: RegisteredSecret; onRemoved: () => void }) {
  const t = useT();
  const { locale } = useLocale();
  const [confirming, setConfirming] = useState(false);
  const label = secret.label.trim() || t('registered-untitled');
  const date = new Intl.DateTimeFormat(locale, { dateStyle: 'medium' }).format(
    new Date(secret.createdAtMs),
  );
  return (
    <li className="flex flex-wrap items-center justify-between gap-2 px-3 py-2">
      <div className="min-w-0">
        <p className="truncate text-sm font-medium">{label}</p>
        <p className="text-xs text-fg-muted">
          {t('ui-desktop-secrets-meta', { length: secret.length, date })}
        </p>
      </div>
      {confirming ? (
        <div className="flex gap-2">
          <Button
            variant="danger"
            onClick={() => {
              ipc
                .removeSecret(secret.id)
                .then(onRemoved)
                .catch(() => {});
            }}
          >
            {t('ui-desktop-secrets-remove-confirm')}
          </Button>
          <Button variant="ghost" onClick={() => setConfirming(false)}>
            {t('ui-desktop-cancel')}
          </Button>
        </div>
      ) : (
        <Button
          variant="ghost"
          aria-label={t('ui-desktop-secrets-remove-label', { label })}
          onClick={() => setConfirming(true)}
        >
          {t('ui-desktop-secrets-remove')}
        </Button>
      )}
    </li>
  );
}

/// Clears every registered secret (keeps the key). The way out when the keyring lost the key
/// while secrets.json still has entries (`store-error-key-missing`), §5.1.
function ForgetSecrets({ onForgotten }: { onForgotten: () => void }) {
  const t = useT();
  const [confirming, setConfirming] = useState(false);
  const [error, setError] = useState<CommandError | null>(null);
  return (
    <div className="grid gap-2">
      <p className="text-xs leading-relaxed text-fg-muted">{t('ui-desktop-secrets-forget-desc')}</p>
      {confirming ? (
        <div className="flex gap-2">
          <Button
            variant="danger"
            onClick={() => {
              ipc
                .forgetSecrets()
                .then(() => {
                  setConfirming(false);
                  setError(null);
                  onForgotten();
                })
                .catch((err) => setError(toCommandError(err)));
            }}
          >
            {t('ui-desktop-secrets-forget-confirm')}
          </Button>
          <Button variant="ghost" onClick={() => setConfirming(false)}>
            {t('ui-desktop-cancel')}
          </Button>
        </div>
      ) : (
        <div>
          <Button variant="ghost" onClick={() => setConfirming(true)}>
            {t('ui-desktop-secrets-forget')}
          </Button>
        </div>
      )}
      {error ? (
        <p role="alert" className="text-xs text-quarantine">
          {t(error.messageId, error.args)}
        </p>
      ) : null}
    </div>
  );
}

export function SecretsManager() {
  const t = useT();
  const [secrets, setSecrets] = useState<RegisteredSecret[] | null>(null);
  const [loadError, setLoadError] = useState<CommandError | null>(null);

  const refresh = useCallback(() => {
    ipc
      .listSecrets()
      .then((list) => {
        setSecrets(list);
        setLoadError(null);
      })
      .catch((err) => setLoadError(toCommandError(err)));
  }, []);

  useEffect(refresh, [refresh]);

  return (
    <div className="grid gap-5">
      <RegisterSecretForm onRegistered={refresh} />
      <div>
        <h3 className="text-sm font-semibold">{t('ui-desktop-secrets-list')}</h3>
        {loadError ? (
          <p role="alert" className="mt-2 text-sm text-quarantine">
            {t(loadError.messageId, loadError.args)}
          </p>
        ) : secrets === null ? null : secrets.length === 0 ? (
          <p className="mt-2 text-sm text-fg-muted">{t('ui-desktop-secrets-none')}</p>
        ) : (
          <ul className="mt-2 divide-y divide-line rounded-lg border border-line">
            {secrets.map((s) => (
              <SecretRow key={s.id} secret={s} onRemoved={refresh} />
            ))}
          </ul>
        )}
      </div>
      {loadError?.messageId === 'store-error-key-missing' || (secrets?.length ?? 0) > 0 ? (
        <ForgetSecrets onForgotten={refresh} />
      ) : null}
    </div>
  );
}
