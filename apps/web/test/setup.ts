import '@testing-library/jest-dom/vitest';
import { cleanup } from '@testing-library/react';
import { afterEach, beforeEach } from 'vitest';

beforeEach(() => {
  if (typeof window === 'undefined') return; // node-environment tests (examples.test.ts)
  localStorage.clear();
  window.history.replaceState(null, '', '/');
  if (!window.matchMedia) {
    Object.defineProperty(window, 'matchMedia', {
      configurable: true,
      value: (query: string) => ({
        matches: false,
        media: query,
        addEventListener: () => {},
        removeEventListener: () => {},
      }),
    });
  }
});

afterEach(() => {
  if (typeof window !== 'undefined') cleanup();
});
