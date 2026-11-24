/** Where a provider persists the user's choice. Synchronous so the first render is correct. */
export interface PreferenceStore {
  get(key: string): string | null;
  set(key: string, value: string): void;
}

/** `localStorage`, guarded: private windows and sandboxed frames can throw on access. */
export const localPreferenceStore: PreferenceStore = {
  get(key) {
    try {
      return globalThis.localStorage?.getItem(key) ?? null;
    } catch {
      return null;
    }
  },
  set(key, value) {
    try {
      globalThis.localStorage?.setItem(key, value);
    } catch {
      // Not persisting is acceptable; the choice still applies for this session.
    }
  },
};

/** Subscribes to a media query; returns the unsubscribe function. Safe without `matchMedia`. */
export function watchMedia(query: string, onChange: (matches: boolean) => void): () => void {
  const mql = globalThis.matchMedia?.(query);
  if (!mql) return () => {};
  const listener = (event: MediaQueryListEvent) => onChange(event.matches);
  mql.addEventListener('change', listener);
  return () => mql.removeEventListener('change', listener);
}

export function mediaMatches(query: string): boolean {
  return globalThis.matchMedia?.(query).matches ?? false;
}
