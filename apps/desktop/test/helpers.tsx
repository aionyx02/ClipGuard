import { render } from '@testing-library/react';
import type { ReactElement } from 'react';
import type { DesktopSettings, ProtectionStatus } from '../src/lib/ipc';
import { DEFAULT_SETTINGS, DesktopRoot } from '../src/ui/DesktopRoot';

export function settings(patch: Partial<DesktopSettings> = {}): DesktopSettings {
  return { ...DEFAULT_SETTINGS, locale: 'en', ...patch };
}

export function renderDesktop(ui: ReactElement, patch: Partial<DesktopSettings> = {}) {
  return render(<DesktopRoot initial={settings(patch)}>{ui}</DesktopRoot>);
}

export const ACTIVE = { state: 'active', reason: null } as const;

export function status(patch: Partial<ProtectionStatus> = {}): ProtectionStatus {
  return {
    watch: ACTIVE,
    write: ACTIVE,
    foreground: ACTIVE,
    intercept: ACTIVE,
    tray: 'normal',
    ...patch,
  };
}
