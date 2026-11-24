// Runs before first paint (blocking, tiny): applies the stored theme and the page language so the
// first frame already matches what React will render. No flash, no layout shift. Mirrors
// ThemeProvider / LocaleProvider in @paste-warden/ui and src/lib/lang.ts.
(() => {
  const root = document.documentElement;
  const read = (key) => {
    try {
      return localStorage.getItem(key);
    } catch {
      return null;
    }
  };
  const theme = read('paste-warden:theme');
  const dark =
    theme === 'dark' ||
    (theme !== 'light' && window.matchMedia?.('(prefers-color-scheme: dark)').matches);
  root.dataset.theme = dark ? 'dark' : 'light';
  root.style.colorScheme = dark ? 'dark' : 'light';

  const pick = (value) => {
    const v = (value || '').toLowerCase();
    if (v.startsWith('zh')) return 'zh-TW';
    if (v.startsWith('en')) return 'en';
    return null;
  };
  let lang =
    pick(new URLSearchParams(location.search).get('lang')) || pick(read('paste-warden:locale'));
  if (!lang) {
    for (const l of navigator.languages || [navigator.language]) {
      lang = pick(l);
      if (lang) break;
    }
  }
  root.lang = lang || 'en';
})();
