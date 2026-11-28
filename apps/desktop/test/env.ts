/** Controllable `prefers-color-scheme: dark` and `navigator.languages`. */
export const media = {
  dark: false,
  listeners: new Set<(e: { matches: boolean }) => void>(),
  setDark(dark: boolean) {
    media.dark = dark;
    for (const l of media.listeners) l({ matches: dark });
  },
};

export function installMatchMedia() {
  media.dark = false;
  media.listeners.clear();
  Object.defineProperty(window, 'matchMedia', {
    configurable: true,
    value: (query: string) => ({
      get matches() {
        return query.includes('dark') ? media.dark : false;
      },
      media: query,
      addEventListener: (_: string, l: (e: { matches: boolean }) => void) => {
        if (query.includes('dark')) media.listeners.add(l);
      },
      removeEventListener: (_: string, l: (e: { matches: boolean }) => void) => {
        media.listeners.delete(l);
      },
    }),
  });
}

export function setLanguages(langs: string[]) {
  Object.defineProperty(navigator, 'languages', { configurable: true, get: () => langs });
  Object.defineProperty(navigator, 'language', { configurable: true, get: () => langs[0] });
}
