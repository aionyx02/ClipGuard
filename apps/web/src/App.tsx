import {
  LocaleProvider,
  localPreferenceStore,
  type PreferenceStore,
  ThemeProvider,
  useLocale,
} from '@paste-warden/ui';
import { useEffect, useMemo } from 'react';
import { Demo } from './components/Demo';
import { ArrowIcon } from './components/icons';
import { Playground } from './components/Playground';
import { Downloads, EngineInfo, Footer, Header, Hero, Privacy } from './components/Sections';
import { urlLocaleStore } from './lib/lang';
import { useView } from './lib/view';
import { useEngine } from './useEngine';

function Home() {
  return (
    <>
      <Hero />
      <Demo />
      <div className="mt-28 grid gap-28">
        <Privacy />
        <Downloads />
      </div>
    </>
  );
}

/** The playground view. The engine (WASM) only loads here, never on the home page. */
function PlayView() {
  const { t } = useLocale();
  const engine = useEngine();
  return (
    <>
      <div className="pt-10 pb-8 sm:pt-14">
        <a
          href="#top"
          className="inline-flex items-center gap-1.5 rounded-l1 text-sm font-medium text-fg-muted hover:text-fg"
        >
          <ArrowIcon className="size-4 rotate-180" />
          {t('ui-web-back-home')}
        </a>
        <h1 className="mt-4 text-3xl font-semibold tracking-tight sm:text-4xl">
          {t('ui-web-playground-title')}
        </h1>
        <p className="mt-3 max-w-2xl text-lg leading-relaxed text-fg-muted text-pretty">
          {t('ui-web-play-lead')}
        </p>
      </div>
      <Playground engine={engine} />
      <EngineInfo engine={engine} />
    </>
  );
}

function Page() {
  const { t } = useLocale();
  const view = useView();

  useEffect(() => {
    document.title = view === 'play' ? t('ui-web-title-play') : t('ui-web-title');
  }, [t, view]);

  return (
    <>
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-50 focus:rounded-l2 focus:bg-surface focus:px-4 focus:py-2 focus:shadow-md"
      >
        {t('ui-web-skip')}
      </a>
      <Header view={view} />
      <main id="main" className="mx-auto max-w-6xl px-4 sm:px-6" data-view={view}>
        <span id="top" />
        {view === 'play' ? <PlayView /> : <Home />}
      </main>
      <Footer />
    </>
  );
}

export function App({ storage = localPreferenceStore }: { storage?: PreferenceStore }) {
  const localeStore = useMemo(() => urlLocaleStore(storage), [storage]);
  return (
    <ThemeProvider storage={storage}>
      <LocaleProvider storage={localeStore}>
        <Page />
      </LocaleProvider>
    </ThemeProvider>
  );
}
