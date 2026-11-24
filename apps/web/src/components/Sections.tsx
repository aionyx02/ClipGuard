import { LocaleSwitcher, ShieldMark, ThemeSwitcher, useLocale } from '@paste-warden/ui';
import { type ReactNode, useId } from 'react';
import { docsUrl, RELEASES_URL, REPO_URL } from '../lib/links';
import type { EngineState } from '../useEngine';
import {
  ArrowIcon,
  BrowserIcon,
  CodeIcon,
  CpuIcon,
  DesktopIcon,
  GitHubIcon,
  LockIcon,
  NoSignalIcon,
  ScriptIcon,
} from './icons';

const LINK = 'rounded-md px-2.5 py-1.5 text-sm text-fg-muted transition-colors hover:text-fg';

export function Header() {
  const { t, locale } = useLocale();
  return (
    <header className="sticky top-0 z-20 border-b border-line bg-canvas/85 backdrop-blur supports-[backdrop-filter]:bg-canvas/70">
      <div className="mx-auto flex h-14 max-w-6xl items-center justify-between gap-3 px-4 sm:px-6">
        <a href="#top" className="flex shrink-0 items-center gap-2 rounded-md">
          <ShieldMark className="size-7" />
          <span className="text-base font-bold tracking-tight">
            Paste<span className="text-accent">Warden</span>
          </span>
          <span className="sr-only">{t('ui-web-tagline')}</span>
        </a>
        <nav aria-label={t('ui-web-nav-label')} className="min-w-0">
          <ul className="flex items-center gap-0.5 overflow-x-auto">
            <li className="hidden sm:block">
              <a href="#playground" className={LINK}>
                {t('ui-web-nav-playground')}
              </a>
            </li>
            <li className="hidden sm:block">
              <a href="#privacy" className={LINK}>
                {t('ui-web-nav-privacy')}
              </a>
            </li>
            <li>
              <a href="#download" className={LINK}>
                {t('ui-web-nav-download')}
              </a>
            </li>
            <li>
              <a href={docsUrl(locale)} className={LINK}>
                {t('ui-web-nav-docs')}
              </a>
            </li>
            <li>
              <a
                href={REPO_URL}
                className={`${LINK} inline-flex items-center`}
                rel="noopener noreferrer"
              >
                <GitHubIcon className="size-5" />
                <span className="sr-only">{t('ui-web-nav-github')}</span>
              </a>
            </li>
          </ul>
        </nav>
      </div>
    </header>
  );
}

export function Hero() {
  const { t } = useLocale();
  return (
    <div className="hero-glow -mx-4 px-4 pt-10 pb-8 sm:-mx-6 sm:px-6 sm:pt-14">
      <div className="flex flex-col gap-6 lg:flex-row lg:items-end lg:justify-between">
        <div className="max-w-2xl">
          <h1 className="text-3xl font-bold tracking-tight text-balance sm:text-4xl">
            {t('ui-web-hero-title')}
          </h1>
          <p className="mt-3 text-base leading-relaxed text-fg-muted text-pretty">
            {t('ui-web-hero-lead')}
          </p>
          <p
            className="mt-4 inline-flex items-center gap-2 rounded-full border border-allow-line bg-allow-bg px-3 py-1.5 text-sm font-medium text-fg"
            data-testid="privacy-badge"
          >
            <LockIcon className="size-4 shrink-0 text-allow" />
            {t('ui-web-privacy-badge')}
          </p>
        </div>
        <section
          aria-label={t('ui-web-prefs-label')}
          className="flex flex-wrap gap-x-5 gap-y-3 lg:justify-end"
        >
          <ThemeSwitcher />
          <LocaleSwitcher />
        </section>
      </div>
    </div>
  );
}

function SectionHeading({ id, title, lead }: { id: string; title: string; lead: string }) {
  return (
    <div className="max-w-2xl">
      <h2 id={id} className="text-2xl font-bold tracking-tight">
        {title}
      </h2>
      <p className="mt-2 text-fg-muted text-pretty">{lead}</p>
    </div>
  );
}

function Point({ icon, title, body }: { icon: ReactNode; title: string; body: string }) {
  return (
    <li className="rounded-card border border-line bg-surface p-5 shadow-card">
      <span className="inline-flex size-10 items-center justify-center rounded-lg bg-allow-bg text-allow">
        {icon}
      </span>
      <h3 className="mt-3 font-semibold">{title}</h3>
      <p className="mt-1 text-sm leading-relaxed text-fg-muted">{body}</p>
    </li>
  );
}

export function Privacy() {
  const { t } = useLocale();
  const id = useId();
  return (
    <section id="privacy" aria-labelledby={id} className="scroll-mt-20">
      <SectionHeading id={id} title={t('ui-web-privacy-title')} lead={t('ui-web-privacy-lead')} />
      <ul className="mt-6 grid gap-4 md:grid-cols-3">
        <Point
          icon={<CpuIcon className="size-5" />}
          title={t('ui-web-privacy-local-title')}
          body={t('ui-web-privacy-local-body')}
        />
        <Point
          icon={<NoSignalIcon className="size-5" />}
          title={t('ui-web-privacy-none-title')}
          body={t('ui-web-privacy-none-body')}
        />
        <Point
          icon={<CodeIcon className="size-5" />}
          title={t('ui-web-privacy-open-title')}
          body={t('ui-web-privacy-open-body')}
        />
      </ul>
    </section>
  );
}

interface Platform {
  key: 'chrome' | 'firefox' | 'userscript' | 'desktop';
  icon: ReactNode;
  guide: string;
  soon?: boolean;
}

const PLATFORMS: Platform[] = [
  { key: 'chrome', icon: <BrowserIcon className="size-5" />, guide: 'user/install/chrome-edge/' },
  { key: 'firefox', icon: <BrowserIcon className="size-5" />, guide: 'user/install/firefox/' },
  { key: 'userscript', icon: <ScriptIcon className="size-5" />, guide: 'user/install/userscript/' },
  {
    key: 'desktop',
    icon: <DesktopIcon className="size-5" />,
    guide: 'user/install/desktop/',
    soon: true,
  },
];

export function Downloads() {
  const { t, locale } = useLocale();
  const id = useId();
  return (
    <section id="download" aria-labelledby={id} className="scroll-mt-20">
      <SectionHeading id={id} title={t('ui-web-download-title')} lead={t('ui-web-download-lead')} />
      <ul className="mt-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {PLATFORMS.map((p) => (
          <li
            key={p.key}
            data-platform={p.key}
            className="flex flex-col rounded-card border border-line bg-surface p-5 shadow-card"
          >
            <div className="flex items-center justify-between gap-2">
              <span className="inline-flex size-10 items-center justify-center rounded-lg bg-surface-2 text-accent">
                {p.icon}
              </span>
              {p.soon && (
                <span className="rounded-full border border-line px-2 py-0.5 text-xs text-fg-muted">
                  {t('ui-web-dl-soon')}
                </span>
              )}
            </div>
            <h3 className="mt-3 font-semibold">{t(`ui-web-dl-${p.key}`)}</h3>
            <p className="mt-1 flex-1 text-sm leading-relaxed text-fg-muted">
              {t(`ui-web-dl-${p.key}-desc`)}
            </p>
            <a
              href={docsUrl(locale, p.guide)}
              className="mt-4 inline-flex items-center gap-1.5 self-start rounded-md text-sm font-semibold text-accent hover:underline"
            >
              {t('ui-web-dl-guide')}
              <span className="sr-only">: {t(`ui-web-dl-${p.key}`)}</span>
              <ArrowIcon className="size-4" />
            </a>
          </li>
        ))}
      </ul>
      <a
        href={RELEASES_URL}
        rel="noopener noreferrer"
        className="mt-6 inline-flex min-h-11 items-center gap-2 rounded-lg bg-ink-900 px-5 text-sm font-semibold text-ink-50 hover:bg-ink-800 dark:bg-brand-300 dark:text-ink-900 dark:hover:bg-brand-200"
      >
        <GitHubIcon className="size-5" />
        {t('ui-web-dl-releases')}
        <span className="sr-only">{t('ui-web-external')}</span>
      </a>
    </section>
  );
}

export function Footer({ engine }: { engine: EngineState }) {
  const { t, locale } = useLocale();
  const ready = engine.status === 'ready' ? engine.engine.core : undefined;
  return (
    <footer className="mt-20 border-t border-line">
      <div className="mx-auto flex max-w-6xl flex-col gap-3 px-4 py-8 text-sm text-fg-muted sm:flex-row sm:items-center sm:justify-between sm:px-6">
        <p className="flex flex-wrap items-center gap-x-4 gap-y-1">
          <span>© PasteWarden · {t('ui-web-footer-license')}</span>
          <a
            href={REPO_URL}
            rel="noopener noreferrer"
            className="underline-offset-2 hover:underline"
          >
            GitHub
          </a>
          <a href={docsUrl(locale)} className="underline-offset-2 hover:underline">
            {t('ui-web-nav-docs')}
          </a>
        </p>
        {/* Fixed height: the line fills in when the engine arrives without moving anything. */}
        <p className="min-h-5 font-mono text-xs" data-testid="engine-info">
          {ready
            ? t('ui-web-footer-engine', {
                version: ready.engineVersion(),
                backend: t(`ui-web-backend-${ready.backend() ?? 'wasm'}`),
              })
            : ''}
        </p>
      </div>
    </footer>
  );
}
