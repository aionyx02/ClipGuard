import { useT } from '@paste-warden/ui';
import {
  AREAS,
  type Capability,
  ipc,
  type ProtectionStatus,
  REASONS,
  type Reason,
} from '../lib/ipc';
import { Button, cx } from './controls';

const ACCESSIBILITY_REASONS: readonly string[] = [
  'no-accessibility',
  'no-accessibility-after-update',
] satisfies Reason[];

export function isReason(value: string | null): value is Reason {
  return value !== null && (REASONS as readonly string[]).includes(value);
}

/** One status message per Reason (§4.9.4); unknown ids get a generic line, never the raw id. */
export function reasonMessageId(reason: string | null): string | null {
  if (reason === null) return null;
  return isReason(reason) ? `ui-desktop-status-${reason}` : 'ui-desktop-status-unknown';
}

const BADGE: Record<Capability['state'], string> = {
  active: 'border-allow-line bg-allow-bg text-allow',
  degraded: 'border-warn-line bg-warn-bg text-warn',
  unavailable: 'border-quarantine-line bg-quarantine-bg text-quarantine',
};

/** The GUI-only steps for re-adding PasteWarden under Accessibility (§4.9.1, roadmap §8). */
export function ReauthorizeSteps() {
  const t = useT();
  return (
    <ol className="mt-2 list-decimal space-y-1 pl-5 text-xs leading-relaxed text-fg">
      {[1, 2, 3, 4].map((n) => (
        <li key={n}>{t(`ui-desktop-reauth-step-${n}`)}</li>
      ))}
    </ol>
  );
}

export function AccessibilityButton() {
  const t = useT();
  return (
    <Button
      variant="primary"
      className="mt-2"
      onClick={() => {
        ipc.openAccessibilitySettings().catch(() => {});
      }}
    >
      {t('ui-desktop-open-accessibility')}
    </Button>
  );
}

function CapabilityRow({ area, cap }: { area: string; cap: Capability }) {
  const t = useT();
  const messageId = cap.state === 'active' ? null : reasonMessageId(cap.reason);
  return (
    <li className="px-3 py-2.5" data-area={area} data-state={cap.state}>
      <div className="flex items-center justify-between gap-3">
        <span className="text-sm font-medium">{t(`ui-desktop-area-${area}`)}</span>
        <span
          className={cx(
            'shrink-0 rounded-full border px-2 py-px text-xs font-semibold',
            BADGE[cap.state],
          )}
        >
          {t(`ui-desktop-state-${cap.state}`)}
        </span>
      </div>
      {messageId ? (
        <p className="mt-1 text-xs leading-relaxed text-fg-muted" data-reason={cap.reason}>
          {t(messageId)}
        </p>
      ) : null}
      {cap.state !== 'active' && cap.reason === 'no-accessibility-after-update' ? (
        <ReauthorizeSteps />
      ) : null}
      {cap.state !== 'active' && cap.reason && ACCESSIBILITY_REASONS.includes(cap.reason) ? (
        <AccessibilityButton />
      ) : null}
    </li>
  );
}

export function StatusCard({ status }: { status: ProtectionStatus | null }) {
  const t = useT();
  if (!status) {
    return (
      <p className="text-sm text-fg-muted" aria-live="polite">
        {t('ui-desktop-status-loading')}
      </p>
    );
  }
  return (
    <div aria-live="polite">
      <p
        className={cx(
          'text-sm font-semibold',
          status.tray === 'normal'
            ? 'text-allow'
            : status.tray === 'degraded'
              ? 'text-warn'
              : 'text-quarantine',
        )}
      >
        {t(`ui-desktop-status-title-${status.tray}`)}
      </p>
      <ul className="mt-2 divide-y divide-line overflow-hidden rounded-lg border border-line bg-surface-2/50">
        {AREAS.map((area) => (
          <CapabilityRow key={area} area={area} cap={status[area]} />
        ))}
      </ul>
    </div>
  );
}
