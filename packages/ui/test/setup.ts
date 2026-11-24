import '@testing-library/jest-dom/vitest';
import { cleanup } from '@testing-library/react';
import { afterEach, beforeEach } from 'vitest';

/** Controllable `matchMedia` (jsdom has none). Tests flip queries with `setMedia`. */
const state = new Map<string, boolean>();
const listeners = new Map<string, Set<(e: MediaQueryListEvent) => void>>();

export function setMedia(query: string, matches: boolean): void {
  state.set(query, matches);
  for (const fn of listeners.get(query) ?? []) {
    fn({ matches, media: query } as MediaQueryListEvent);
  }
}

beforeEach(() => {
  state.clear();
  listeners.clear();
  localStorage.clear();
  document.documentElement.removeAttribute('data-theme');
  Object.defineProperty(window, 'matchMedia', {
    configurable: true,
    value: (query: string) => ({
      get matches() {
        return state.get(query) ?? false;
      },
      media: query,
      addEventListener: (_: string, fn: (e: MediaQueryListEvent) => void) => {
        if (!listeners.has(query)) listeners.set(query, new Set());
        listeners.get(query)?.add(fn);
      },
      removeEventListener: (_: string, fn: (e: MediaQueryListEvent) => void) => {
        listeners.get(query)?.delete(fn);
      },
    }),
  });
});

afterEach(() => cleanup());
