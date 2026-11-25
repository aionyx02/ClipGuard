// First run (§4.8.3, §4.9.1): welcome → what is not protected (must be acknowledged with
// 「我知道了」) → macOS Accessibility (macOS only) → done, which calls `complete_onboarding`.
import { LocaleSwitcher, ShieldMark, ThemeSwitcher, useT } from '@paste-warden/ui';
import { type ReactNode, useEffect, useId, useRef, useState } from 'react';
import { ipc, type Platform } from '../lib/ipc';
import { Button } from '../ui/controls';
import { useSettings } from '../ui/DesktopRoot';
import { ScopeTable } from '../ui/ScopeTable';
import { AccessibilityButton, ReauthorizeSteps } from '../ui/StatusCard';
import { useProtectionStatus } from '../ui/useProtectionStatus';

export type Step = 'welcome' | 'limits' | 'accessibility' | 'done';

export function stepsFor(platform: Platform): Step[] {
  return platform === 'macos'
    ? ['welcome', 'limits', 'accessibility', 'done']
    : ['welcome', 'limits', 'done'];
}

function Page({
  title,
  children,
  actions,
  step,
  total,
}: {
  title: string;
  children: ReactNode;
  actions: ReactNode;
  step: number;
  total: number;
}) {
  const t = useT();
  const headingRef = useRef<HTMLHeadingElement>(null);
  const id = useId();
  // Move focus to the new page's heading so screen readers announce it.
  // biome-ignore lint/correctness/useExhaustiveDependencies: run once per page
  useEffect(() => {
    headingRef.current?.focus();
  }, [title]);
  return (
    <section aria-labelledby={id} className="flex min-h-screen flex-col gap-4 p-6">
      <p className="text-xs font-medium text-fg-muted">
        {t('ui-desktop-onboarding-progress', { step, total })}
      </p>
      <h1 id={id} ref={headingRef} tabIndex={-1} className="text-xl font-bold tracking-tight">
        {title}
      </h1>
      <div className="grid gap-3 text-sm leading-relaxed">{children}</div>
      <div className="mt-auto flex flex-wrap justify-end gap-2 pt-4">{actions}</div>
    </section>
  );
}

function MacAccessibility() {
  const t = useT();
  const { settings } = useSettings();
  const status = useProtectionStatus();
  const intercept = status?.intercept;
  const granted = intercept?.state === 'active';
  const afterUpdate =
    intercept?.reason === 'no-accessibility-after-update' ||
    (settings.versionChanged && !granted && intercept?.reason === 'no-accessibility');
  const askPasteboard = status?.watch.reason === 'pasteboard-access-ask';
  return (
    <>
      <p>{t('ui-desktop-onboarding-mac-accessibility-why')}</p>
      <p className="text-fg-muted">{t('ui-desktop-onboarding-mac-accessibility-without')}</p>
      {afterUpdate ? (
        <div className="rounded-lg border border-warn-line bg-warn-bg p-3 text-warn">
          <p className="font-medium">{t('ui-desktop-status-no-accessibility-after-update')}</p>
          <ReauthorizeSteps />
        </div>
      ) : (
        <ol className="list-decimal space-y-1 pl-5">
          <li>{t('ui-desktop-onboarding-mac-step-1')}</li>
          <li>{t('ui-desktop-onboarding-mac-step-2')}</li>
          <li>{t('ui-desktop-onboarding-mac-step-3')}</li>
        </ol>
      )}
      <div>
        {granted ? (
          <p role="status" className="font-medium text-allow">
            {t('ui-desktop-onboarding-mac-granted')}
          </p>
        ) : (
          <AccessibilityButton />
        )}
      </div>
      {askPasteboard ? (
        <p className="rounded-lg border border-warn-line bg-warn-bg p-3 text-warn">
          {t('ui-desktop-status-pasteboard-access-ask')}
        </p>
      ) : null}
    </>
  );
}

export function App() {
  const t = useT();
  const { settings } = useSettings();
  const status = useProtectionStatus();
  const steps = stepsFor(settings.platform);
  const [index, setIndex] = useState(0);
  const [finishing, setFinishing] = useState(false);
  const step = steps[index] ?? 'done';
  const next = () => setIndex((i) => Math.min(i + 1, steps.length - 1));
  const back = () => setIndex((i) => Math.max(i - 1, 0));

  useEffect(() => {
    document.title = t('ui-desktop-onboarding-title');
  }, [t]);

  const common = { step: index + 1, total: steps.length };
  const backButton =
    index > 0 ? (
      <Button variant="ghost" onClick={back}>
        {t('ui-desktop-onboarding-back')}
      </Button>
    ) : null;

  if (step === 'welcome') {
    return (
      <Page
        {...common}
        title={t('ui-desktop-onboarding-welcome-title')}
        actions={
          <Button variant="primary" onClick={next}>
            {t('ui-desktop-onboarding-next')}
          </Button>
        }
      >
        <ShieldMark className="size-12" />
        <p>{t('ui-desktop-onboarding-welcome-1')}</p>
        <p>{t('ui-desktop-onboarding-welcome-2')}</p>
        <p className="text-fg-muted">{t('ui-desktop-onboarding-welcome-privacy')}</p>
        <div className="flex flex-wrap gap-6">
          <LocaleSwitcher />
          <ThemeSwitcher />
        </div>
      </Page>
    );
  }

  if (step === 'limits') {
    return (
      <Page
        {...common}
        title={t('ui-desktop-onboarding-limits-title')}
        actions={
          <>
            {backButton}
            <Button variant="primary" onClick={next}>
              {t('ui-desktop-onboarding-limits-ack')}
            </Button>
          </>
        }
      >
        <p>{t('ui-desktop-onboarding-limits-intro')}</p>
        <p>{t('ui-desktop-onboarding-limits-commands')}</p>
        <p className="font-medium text-warn">{t('ui-desktop-onboarding-limits-secrets')}</p>
        <ScopeTable platform={settings.platform} status={status} />
        <p className="text-fg-muted">{t('ui-desktop-onboarding-limits-later')}</p>
      </Page>
    );
  }

  if (step === 'accessibility') {
    return (
      <Page
        {...common}
        title={t('ui-desktop-onboarding-mac-accessibility-title')}
        actions={
          <>
            {backButton}
            <Button variant="primary" onClick={next}>
              {t('ui-desktop-onboarding-next')}
            </Button>
          </>
        }
      >
        <MacAccessibility />
      </Page>
    );
  }

  return (
    <Page
      {...common}
      title={t('ui-desktop-onboarding-done-title')}
      actions={
        <>
          {backButton}
          <Button
            variant="primary"
            disabled={finishing}
            onClick={() => {
              setFinishing(true);
              ipc
                .completeOnboarding()
                .catch(() => {})
                .finally(() => setFinishing(false));
            }}
          >
            {t('ui-desktop-onboarding-finish')}
          </Button>
        </>
      }
    >
      <p>{t('ui-desktop-onboarding-done-1')}</p>
      <p>{t('ui-desktop-onboarding-done-2')}</p>
    </Page>
  );
}
