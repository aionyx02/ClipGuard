import { LocaleSwitcher, ShieldMark, ThemeSwitcher, useLocale } from '@paste-warden/ui';
import { type ReactNode, useId } from 'react';
import { docsUrl, RELEASES_URL, REPO_URL } from '../lib/links';
import { PLAY_HASH, type View } from '../lib/view';
import { badge, button, CARD, ICON_TILE } from '../park/recipes';
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

const LINK =
  'rounded-l1 px-2.5 py-1.5 text-sm font-medium text-fg-muted transition-colors hover:bg-gray-a3 hover:text-fg';

export function Header({ view }: { view: View }) {
  const { t, locale } = useLocale();
  return (
    <header className="sticky top-0 z-20 border-b border-border-muted bg-canvas/80 backdrop-blur-md">
      <div className="mx-auto flex h-16 max-w-6xl items-center justify-between gap-3 px-4 sm:px-6">
        <a href="#top" className="flex shrink-0 items-center gap-2 rounded-md">
          <ShieldMark className="size-7" />
          <span className="text-[0.9375rem] font-semibold tracking-tight">PasteWarden</span>
          <span className="sr-only">{t('ui-web-tagline')}</span>
        </a>
        <nav aria-label={t('ui-web-nav-label')} className="min-w-0">
          <ul className="flex items-center gap-0.5 overflow-x-auto">
            <li className="hidden sm:block">
              <a
                href={PLAY_HASH}
                className={`${LINK} aria-[current=page]:text-fg`}
                aria-current={view === 'play' ? 'page' : undefined}
              >
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
    <div className="relative -mx-4 px-4 pt-16 pb-6 sm:-mx-6 sm:px-6 sm:pt-24">
      <div aria-hidden="true" className="hero-grid pointer-events-none absolute inset-0 -z-10" />
      <div className="mx-auto flex max-w-3xl flex-col items-center text-center">
        <p className={`${badge('outline')} py-1 text-sm`} data-testid="privacy-badge">
          <LockIcon className="size-3.5 shrink-0" />
          {t('ui-web-privacy-badge')}
        </p>
        <h1 className="mt-6 text-4xl font-semibold tracking-tight text-balance sm:text-6xl sm:leading-[1.05]">
          {t('ui-web-hero-title')}
        </h1>
        <p className="mt-6 max-w-2xl text-lg leading-relaxed text-fg-muted text-pretty">
          {t('ui-web-hero-lead')}
        </p>
        <a href={PLAY_HASH} className={`${button({ size: 'lg' })} mt-9`} data-testid="cta-play">
          {t('ui-web-nav-playground')}
          <ArrowIcon className="size-4" />
        </a>
      </div>
    </div>
  );
}

function SectionHeading({ id, title, lead }: { id: string; title: string; lead: string }) {
  return (
    <div className="max-w-2xl">
      <h2 id={id} className="text-3xl font-semibold tracking-tight">
        {title}
      </h2>
      <p className="mt-3 text-lg leading-relaxed text-fg-muted text-pretty">{lead}</p>
    </div>
  );
}

function Point({ icon, title, body }: { icon: ReactNode; title: string; body: string }) {
  return (
    <li className={`${CARD} p-6`}>
      <span className={ICON_TILE}>{icon}</span>
      <h3 className="mt-4 font-semibold">{title}</h3>
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
      <ul className="mt-8 grid gap-4 md:grid-cols-3">
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
      <ul className="mt-8 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {PLATFORMS.map((p) => (
          <li
            key={p.key}
            data-platform={p.key}
            className={`${CARD} group flex flex-col p-6 transition-shadow hover:shadow-md`}
          >
            <div className="flex items-center justify-between gap-2">
              <span className={ICON_TILE}>{p.icon}</span>
              {p.soon && <span className={badge('outline')}>{t('ui-web-dl-soon')}</span>}
            </div>
            <h3 className="mt-4 font-semibold">{t(`ui-web-dl-${p.key}`)}</h3>
            <p className="mt-1 flex-1 text-sm leading-relaxed text-fg-muted">
              {t(`ui-web-dl-${p.key}-desc`)}
            </p>
            <a
              href={docsUrl(locale, p.guide)}
              className="mt-5 inline-flex items-center gap-1.5 self-start rounded-l1 text-sm font-semibold text-accent underline-offset-4 hover:underline"
            >
              {t('ui-web-dl-guide')}
              <span className="sr-only">: {t(`ui-web-dl-${p.key}`)}</span>
              <ArrowIcon className="size-4" />
            </a>
          </li>
        ))}
      </ul>
      <a href={RELEASES_URL} rel="noopener noreferrer" className={`${button({ size: 'lg' })} mt-8`}>
        <GitHubIcon className="size-5" />
        {t('ui-web-dl-releases')}
        <span className="sr-only">{t('ui-web-external')}</span>
      </a>
    </section>
  );
}

/** Engine version line under the playground. Fixed height: it fills in without moving anything. */
export function EngineInfo({ engine }: { engine: EngineState }) {
  const { t } = useLocale();
  const ready = engine.status === 'ready' ? engine.engine.core : undefined;
  return (
    <p className="mt-6 min-h-5 font-mono text-xs text-fg-muted" data-testid="engine-info">
      {ready
        ? t('ui-web-footer-engine', {
            version: ready.engineVersion(),
            backend: t(`ui-web-backend-${ready.backend() ?? 'wasm'}`),
          })
        : ''}
    </p>
  );
}

export function Footer() {
  const { t, locale } = useLocale();
  return (
    <footer className="mt-24 border-t border-border-muted bg-bg-subtle">
      <div className="mx-auto flex max-w-6xl flex-col gap-6 px-4 py-10 text-sm text-fg-muted sm:px-6 md:flex-row md:items-end md:justify-between">
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
        <section aria-label={t('ui-web-prefs-label')} className="flex flex-wrap gap-x-5 gap-y-3">
          <ThemeSwitcher />
          <LocaleSwitcher />
        </section>
      </div>
    </footer>
  );
}
