// The contract with apps/desktop/src-tauri (docs/plan/phase-4.md §4.3 UI commands, §4.8.1).
// Every call goes through here so the shapes live in one place and tests can mock
// `@tauri-apps/api`.
import { invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';

export type CapabilityState = 'active' | 'degraded' | 'unavailable';

/** `Reason::id()` in crates/platform/src/status.rs; message `ui-desktop-status-<id>`. */
export const REASONS = [
  'hook-lost',
  'elevated-foreground',
  'disabled-in-settings',
  'secure-input',
  'no-accessibility',
  'no-accessibility-after-update',
  'pasteboard-access-ask',
  'pasteboard-access-denied',
  'no-data-control',
  'xwayland-unverified',
  'cosmic-disabled',
  'no-foreign-toplevel',
  'wayland-no-intercept',
  'x11-no-intercept',
  'no-display',
  'no-secret-service',
  'android-no-background',
  'host-failed',
] as const;
export type Reason = (typeof REASONS)[number];

export interface Capability {
  state: CapabilityState;
  reason: string | null;
}

export const AREAS = ['watch', 'write', 'foreground', 'intercept'] as const;
export type Area = (typeof AREAS)[number];

export interface ProtectionStatus {
  watch: Capability;
  write: Capability;
  foreground: Capability;
  intercept: Capability;
  tray: 'normal' | 'degraded' | 'failed';
}

export type LocaleSetting = 'system' | 'zh-TW' | 'en';
export type ThemeSetting = 'system' | 'light' | 'dark';
export type Platform = 'windows' | 'macos' | 'linux';

export interface DesktopSettings {
  locale: LocaleSetting;
  theme: ThemeSetting;
  pasteGuard: { registered: boolean; detected: boolean; allowlist: string[] };
  onboardingDone: boolean;
  platform: Platform;
  /** The app version differs from the last run (macOS re-authorization after an update). */
  versionChanged: boolean;
}

export interface RegisteredSecret {
  id: string;
  label: string;
  /** Length in characters. The secret itself never leaves Rust. */
  length: number;
  createdAtMs: number;
}

export type PasteChoice = 'cancel' | 'masked' | 'original';

export interface PasteConfirmRequest {
  /** Message ids, one per kind of secret on the clipboard. */
  kinds: string[];
  /** Already masked by Rust. */
  maskedPreview: string;
  targetName: string | null;
}

/** What a failed command rejects with. `args` is optional (see the report: contract gap). */
export interface CommandError {
  messageId: string;
  field?: string | null;
  args?: Record<string, string | number>;
}

export const FALLBACK_ERROR = 'ui-desktop-error-generic';

/** Normalizes whatever a rejected `invoke` produced into a {@link CommandError}. */
export function toCommandError(error: unknown): CommandError {
  if (error && typeof error === 'object' && 'messageId' in error) {
    const e = error as Record<string, unknown>;
    if (typeof e.messageId === 'string' && /^[a-z][a-z0-9-]*$/.test(e.messageId)) {
      const field = typeof e.field === 'string' ? e.field : null;
      const args =
        e.args && typeof e.args === 'object'
          ? Object.fromEntries(
              Object.entries(e.args as Record<string, unknown>).filter(
                (kv): kv is [string, string | number] =>
                  typeof kv[1] === 'string' || typeof kv[1] === 'number',
              ),
            )
          : undefined;
      return { messageId: e.messageId, field, args };
    }
  }
  // Never surface a raw error string: it could echo input back.
  return { messageId: FALLBACK_ERROR, field: null };
}

export const ipc = {
  getProtectionStatus: () => invoke<ProtectionStatus>('get_protection_status'),
  getSettings: () => invoke<DesktopSettings>('get_settings'),
  setLocale: (locale: LocaleSetting) => invoke<void>('set_locale', { locale }),
  setTheme: (theme: ThemeSetting) => invoke<void>('set_theme', { theme }),
  setPasteGuard: (registered: boolean, detected: boolean) =>
    invoke<void>('set_paste_guard', { registered, detected }),
  allowlistAdd: (name: string) => invoke<void>('allowlist_add', { name }),
  allowlistRemove: (name: string) => invoke<void>('allowlist_remove', { name }),
  completeOnboarding: () => invoke<void>('complete_onboarding'),
  openAccessibilitySettings: () => invoke<void>('open_accessibility_settings'),
  registerSecret: (secret: string, confirm: string, label: string) =>
    invoke<{ id: string }>('register_secret', { secret, confirm, label }),
  listSecrets: () => invoke<RegisteredSecret[]>('list_secrets'),
  removeSecret: (id: string) => invoke<void>('remove_secret', { id }),
  forgetSecrets: () => invoke<void>('forget_secrets'),
  pasteChoice: (choice: PasteChoice) => invoke<void>('paste_choice', { choice }),
  quit: () => invoke<void>('quit'),
};

export const events = {
  protectionStatus: (cb: (s: ProtectionStatus) => void): Promise<UnlistenFn> =>
    listen<ProtectionStatus>('protection-status', (e) => cb(e.payload)),
  settingsChanged: (cb: (s: DesktopSettings) => void): Promise<UnlistenFn> =>
    listen<DesktopSettings>('settings-changed', (e) => cb(e.payload)),
  pasteConfirm: (cb: (r: PasteConfirmRequest) => void): Promise<UnlistenFn> =>
    listen<PasteConfirmRequest>('paste-confirm', (e) => cb(e.payload)),
};

/** Subscribes in an effect; handles the unlisten promise resolving after unmount. */
export function subscribe(start: () => Promise<UnlistenFn>): () => void {
  let unlisten: UnlistenFn | null = null;
  let done = false;
  start()
    .then((fn) => {
      if (done) fn();
      else unlisten = fn;
    })
    .catch(() => {});
  return () => {
    done = true;
    unlisten?.();
  };
}
