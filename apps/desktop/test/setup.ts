import '@testing-library/jest-dom/vitest';
import { cleanup } from '@testing-library/react';
import { afterEach, beforeEach, vi } from 'vitest';
import { installMatchMedia, setLanguages } from './env';
import { resetTauri } from './tauri';

vi.mock('@tauri-apps/api/core', async () => ({ invoke: (await import('./tauri')).invoke }));
vi.mock('@tauri-apps/api/event', async () => ({ listen: (await import('./tauri')).listen }));
vi.mock('@tauri-apps/api/app', () => ({ getVersion: async () => '0.0.0-test' }));

beforeEach(() => {
  resetTauri();
  installMatchMedia();
  setLanguages(['en-US']);
});

afterEach(() => {
  cleanup();
  delete document.documentElement.dataset.theme;
});
