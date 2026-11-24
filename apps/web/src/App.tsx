import {
  LocaleProvider,
  localPreferenceStore,
  type PreferenceStore,
  ThemeProvider,
  useLocale,
} from '@paste-warden/ui';
import { useEffect, useMemo } from 'react';
import { Playground } from './components/Playground';
import { Downloads, Footer, Header, Hero, Privacy } from './components/Sections';
import { urlLocaleStore } from './lib/lang';
import { useEngine } from './useEngine';

function Page() {
  const { t } = useLocale();
  const engine = useEngine();

  useEffect(() => {
    document.title = t('ui-web-title');
  }, [t]);

  return (
    <>
      <a
        href="#playground"
        className="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-50 focus:rounded-lg focus:bg-surface focus:px-4 focus:py-2 focus:shadow-card"
      >
        {t('ui-web-skip')}
      </a>
      <Header />
      <main id="top" className="mx-auto max-w-6xl px-4 sm:px-6">
        <Hero />
        <Playground engine={engine} />
        <div className="mt-20 grid gap-20">
          <Privacy />
          <Downloads />
        </div>
      </main>
      <Footer engine={engine} />
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
