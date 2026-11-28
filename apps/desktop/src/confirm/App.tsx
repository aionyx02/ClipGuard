// Paste confirmation (§4.4 paste interception, §5.3). The safe answer is always one key away:
// focus starts on Cancel, and Enter or Esc cancels from anywhere in the window — Enter included,
// because a user who was mid-typing in the target app should not paste by accident.
// The other buttons still work with the mouse or Tab + Space.
import { useT } from '@paste-warden/ui';
import { useCallback, useEffect, useRef, useState } from 'react';
import { events, ipc, type PasteChoice, type PasteConfirmRequest, subscribe } from '../lib/ipc';
import { Button } from '../ui/controls';

/**
 * `kinds` are message ids. Tolerates a bare core kind (`credit_card`) by mapping it to
 * `ui-desktop-kind-credit-card`.
 */
export function kindMessageId(kind: string): string {
  if (/^[a-z][a-z0-9-]*$/.test(kind) && kind.includes('-')) return kind;
  if (/^[a-z][a-z0-9_]*$/.test(kind)) return `ui-desktop-kind-${kind.replaceAll('_', '-')}`;
  return 'ui-desktop-kind-other';
}

export interface ConfirmDialogProps {
  request: PasteConfirmRequest;
  onChoice: (choice: PasteChoice) => void;
  busy?: boolean;
}

export function ConfirmDialog({ request, onChoice, busy }: ConfirmDialogProps) {
  const t = useT();
  const cancelRef = useRef<HTMLButtonElement>(null);

  // biome-ignore lint/correctness/useExhaustiveDependencies: refocus Cancel for every new request
  useEffect(() => {
    cancelRef.current?.focus();
  }, [request]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape' || e.key === 'Enter') {
        e.preventDefault();
        e.stopPropagation();
        if (!busy) onChoice('cancel');
      }
    };
    window.addEventListener('keydown', onKey, true);
    return () => window.removeEventListener('keydown', onKey, true);
  }, [onChoice, busy]);

  const kinds = [...new Set(request.kinds.map(kindMessageId))].map((id) => t(id));
  const target = request.targetName?.trim();

  return (
    <div
      role="alertdialog"
      aria-modal="true"
      aria-labelledby="confirm-title"
      aria-describedby="confirm-desc"
      className="flex min-h-screen flex-col gap-4 bg-canvas p-5 text-fg"
    >
      <div>
        <h1 id="confirm-title" className="text-lg font-semibold">
          {t('ui-desktop-confirm-title')}
        </h1>
        <p id="confirm-desc" className="mt-1 text-sm text-fg-muted">
          {target ? t('ui-desktop-confirm-desc-target', { target }) : t('ui-desktop-confirm-desc')}
        </p>
      </div>
      {kinds.length > 0 ? (
        <div>
          <h2 className="text-xs font-medium text-fg-muted">{t('ui-desktop-confirm-kinds')}</h2>
          <ul className="mt-1 flex flex-wrap gap-1.5">
            {kinds.map((k) => (
              <li
                key={k}
                className="rounded-full border border-quarantine-line bg-quarantine-bg px-2.5 py-0.5 text-xs font-medium text-quarantine"
              >
                {k}
              </li>
            ))}
          </ul>
        </div>
      ) : null}
      <div>
        <h2 className="text-xs font-medium text-fg-muted">{t('ui-desktop-confirm-preview')}</h2>
        <pre className="mt-1 max-h-40 overflow-auto rounded-lg bg-ink-900 p-3 font-mono text-xs whitespace-pre-wrap break-all text-brand-200 dark:bg-ink-950">
          {request.maskedPreview}
        </pre>
      </div>
      <p className="text-xs text-fg-muted">{t('ui-desktop-confirm-keys')}</p>
      <div className="mt-auto flex flex-wrap justify-end gap-2">
        <Button
          variant="ghost"
          disabled={busy}
          onClick={() => onChoice('original')}
          className="text-quarantine"
        >
          {t('ui-desktop-confirm-original')}
        </Button>
        <Button variant="secondary" disabled={busy} onClick={() => onChoice('masked')}>
          {t('ui-desktop-confirm-masked')}
        </Button>
        <Button
          ref={cancelRef}
          variant="primary"
          disabled={busy}
          onClick={() => onChoice('cancel')}
        >
          {t('ui-desktop-confirm-cancel')}
        </Button>
      </div>
    </div>
  );
}

export function App() {
  const t = useT();
  const [request, setRequest] = useState<PasteConfirmRequest | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    document.title = t('ui-desktop-confirm-title');
  }, [t]);

  useEffect(
    () =>
      subscribe(() =>
        events.pasteConfirm((r) => {
          setBusy(false);
          setRequest(r);
        }),
      ),
    [],
  );

  const choose = useCallback((choice: PasteChoice) => {
    setBusy(true);
    ipc
      .pasteChoice(choice)
      .catch(() => {})
      .finally(() => {
        // Rust hides the window; drop the preview so nothing lingers in the DOM.
        setRequest(null);
        setBusy(false);
      });
  }, []);

  if (!request) {
    return (
      <p className="p-5 text-sm text-fg-muted" aria-live="polite">
        {t('ui-desktop-confirm-waiting')}
      </p>
    );
  }
  return <ConfirmDialog request={request} onChoice={choose} busy={busy} />;
}
