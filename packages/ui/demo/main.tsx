import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { fixtureReports } from '../src/fixtures/reports';
import {
  LocaleProvider,
  LocaleSwitcher,
  MaskPreview,
  OnionTrace,
  SecretList,
  ShieldMark,
  ThemeProvider,
  ThemeSwitcher,
  useLocale,
  VerdictCard,
} from '../src/index';
import './demo.css';

/** Component gallery with fixture Reports (no engine needed). */
function Gallery() {
  const { locale } = useLocale();
  const f = fixtureReports(locale);
  return (
    <div className="mx-auto max-w-6xl px-4 py-8 sm:px-6">
      <header className="flex flex-wrap items-end justify-between gap-4 border-b border-line pb-6">
        <div className="flex items-center gap-3">
          <ShieldMark className="size-11" />
          <div>
            <h1 className="text-2xl font-bold tracking-tight">
              Paste<span className="text-accent">Warden</span>
            </h1>
            <p className="text-sm text-fg-muted">@paste-warden/ui</p>
          </div>
        </div>
        <div className="flex flex-wrap gap-4">
          <ThemeSwitcher />
          <LocaleSwitcher />
        </div>
      </header>

      <main className="mt-8 grid items-start gap-6 lg:grid-cols-2">
        <VerdictCard report={f.clickfix} />
        <OnionTrace trace={f.clickfix.command.trace} tone={f.clickfix.action} />
        <VerdictCard report={f.warn} />
        <div className="grid gap-6">
          <SecretList secrets={f.secrets.secrets} />
          <MaskPreview masked={f.secretsMaskedText} secrets={f.secrets.secrets} />
        </div>
        <VerdictCard report={f.clean} className="lg:col-span-2" />
      </main>
    </div>
  );
}

const root = document.getElementById('root');
if (root) {
  createRoot(root).render(
    <StrictMode>
      <ThemeProvider>
        <LocaleProvider>
          <Gallery />
        </LocaleProvider>
      </ThemeProvider>
    </StrictMode>,
  );
}
