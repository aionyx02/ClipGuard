import { LocaleSwitcher, ShieldMark, ThemeSwitcher, useT } from '@paste-warden/ui';
import { getVersion } from '@tauri-apps/api/app';
import { useEffect, useState } from 'react';
import { ipc } from '../lib/ipc';
import { Button, Section } from '../ui/controls';
import { useSettings } from '../ui/DesktopRoot';
import { PlatformLimits, ScopeTable } from '../ui/ScopeTable';
import { StatusCard } from '../ui/StatusCard';
import { useProtectionStatus } from '../ui/useProtectionStatus';
import { Allowlist, PasteGuardSwitches } from './PasteGuard';
import { SecretsManager } from './Secrets';

function About() {
  const t = useT();
  const [version, setVersion] = useState<string | null>(null);
  useEffect(() => {
    getVersion()
      .then(setVersion)
      .catch(() => {});
  }, []);
  return (
    <div className="grid gap-3 text-sm">
      <p>
        {t('ui-desktop-about-version', { version: version ?? '—' })}
        <br />
        <span className="text-fg-muted">{t('ui-desktop-about-privacy')}</span>
      </p>
      <div>
        <Button
          variant="danger"
          onClick={() => {
            ipc.quit().catch(() => {});
          }}
        >
          {t('ui-desktop-quit')}
        </Button>
      </div>
    </div>
  );
}

export function App() {
  const t = useT();
  const { settings } = useSettings();
  const status = useProtectionStatus();

  useEffect(() => {
    document.title = t('ui-desktop-settings-title');
  }, [t]);

  return (
    <div className="min-h-screen bg-canvas text-fg">
      <div className="mx-auto max-w-2xl px-4 py-8 sm:px-6">
        <header className="flex items-center gap-3">
          <ShieldMark className="size-10" />
          <div>
            <h1 className="text-xl font-bold tracking-tight">{t('ui-desktop-settings-title')}</h1>
            <p className="text-sm text-fg-muted">{t('ui-desktop-settings-subtitle')}</p>
          </div>
        </header>
        <main className="mt-6 grid gap-5">
          <Section title={t('ui-desktop-section-status')}>
            <StatusCard status={status} />
          </Section>
          <Section
            title={t('ui-desktop-section-paste-guard')}
            description={t('ui-desktop-section-paste-guard-desc')}
          >
            <PasteGuardSwitches />
          </Section>
          <Section
            title={t('ui-desktop-section-allowlist')}
            description={t('ui-desktop-section-allowlist-desc')}
          >
            <Allowlist />
          </Section>
          <Section
            title={t('ui-desktop-section-secrets')}
            description={t('ui-desktop-section-secrets-desc')}
          >
            <SecretsManager />
          </Section>
          <Section
            id="scope"
            title={t('ui-desktop-section-scope')}
            description={t('ui-desktop-section-scope-desc')}
          >
            <ScopeTable platform={settings.platform} status={status} />
          </Section>
          <Section title={t('ui-desktop-section-limits', { platform: settings.platform })}>
            <PlatformLimits platform={settings.platform} />
          </Section>
          <Section
            title={t('ui-desktop-section-appearance')}
            description={t('ui-desktop-section-appearance-desc')}
          >
            <div className="flex flex-wrap gap-6">
              <LocaleSwitcher />
              <ThemeSwitcher />
            </div>
          </Section>
          <Section title={t('ui-desktop-section-about')}>
            <About />
          </Section>
        </main>
      </div>
    </div>
  );
}
