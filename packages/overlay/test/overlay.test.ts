import { fixtureReports } from '@paste-warden/ui/fixtures';
import type { TraceKind } from '@paste-warden/ui/report';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  closeOverlay,
  parseFtl,
  showClipboardBlocked,
  showPasteConfirm,
  systemLocale,
} from '../src/index';
import { CSS } from '../src/styles';

const zh = fixtureReports('zh-TW');
const en = fixtureReports('en');

/** The overlay uses a closed shadow root; capture it so tests can look inside. */
let shadow: ShadowRoot | null = null;
const realAttach = Element.prototype.attachShadow;

beforeEach(() => {
  shadow = null;
  vi.spyOn(Element.prototype, 'attachShadow').mockImplementation(function (
    this: Element,
    init: ShadowRootInit,
  ) {
    expect(init.mode).toBe('closed');
    shadow = realAttach.call(this, init);
    return shadow;
  });
});

afterEach(() => {
  closeOverlay();
  vi.restoreAllMocks();
  vi.useRealTimers();
  document.body.innerHTML = '';
});

const q = <T extends Element = HTMLElement>(sel: string) => shadow?.querySelector<T>(sel) ?? null;
const button = (name: string) =>
  [...(shadow?.querySelectorAll('button') ?? [])].find((b) => b.textContent === name) ?? null;
const press = (key: string, init: KeyboardEventInit = {}) => {
  const target = (shadow?.activeElement ?? q('dialog')) as HTMLElement;
  const event = new KeyboardEvent('keydown', {
    key,
    bubbles: true,
    cancelable: true,
    composed: true,
    ...init,
  });
  target.dispatchEvent(event);
  return event;
};
const test = { trustedEventsOnly: false, armDelayMs: 0 } as const;

describe('showClipboardBlocked', () => {
  it('renders a modal dialog with source, reasons and a collapsed onion view', async () => {
    const result = showClipboardBlocked(zh.clickfix, {
      ...test,
      locale: 'zh-TW',
      url: 'https://example.invalid/captcha?id=1',
    });
    const host = document.documentElement.querySelector('paste-warden-overlay');
    expect(host).not.toBeNull();
    const dialog = q<HTMLDialogElement>('dialog');
    expect(dialog?.getAttribute('aria-modal')).toBe('true');
    expect(q('#pw-t')?.textContent).toBe('已攔下網站放進剪貼簿的指令');
    expect(q('.src code')?.textContent).toBe('https://example.invalid/captcha');
    expect(shadow?.querySelectorAll('.bdy ul li')).toHaveLength(4);
    const details = q<HTMLDetailsElement>('details');
    expect(details?.open).toBe(false);
    expect(details?.querySelectorAll('ol li')).toHaveLength(4);
    expect(q('summary')?.textContent).toBe('解混淆過程（4 層）');
    // "Keep blocked" is focused by default.
    expect(shadow?.activeElement?.textContent).toBe('繼續封鎖');
    button('繼續封鎖')?.click();
    await expect(result).resolves.toBe('keep-blocked');
    expect(document.querySelector('paste-warden-overlay')).toBeNull();
  });

  it('allow once resolves allow-once', async () => {
    const result = showClipboardBlocked(en.clickfix, {
      ...test,
      locale: 'en',
      url: 'https://example.invalid/',
    });
    button("I'm sure it's safe, allow once")?.click();
    await expect(result).resolves.toBe('allow-once');
  });

  it('Esc and Enter keep it blocked, even with focus on "allow once"', async () => {
    const a = showClipboardBlocked(en.clickfix, {
      ...test,
      locale: 'en',
      url: 'https://example.invalid/',
    });
    press('Escape');
    await expect(a).resolves.toBe('keep-blocked');

    const b = showClipboardBlocked(en.clickfix, {
      ...test,
      locale: 'en',
      url: 'https://example.invalid/',
    });
    button("I'm sure it's safe, allow once")?.focus();
    const event = press('Enter');
    expect(event.defaultPrevented).toBe(true);
    await expect(b).resolves.toBe('keep-blocked');
  });

  it('ignores synthetic clicks on "allow once" by default', async () => {
    const result = showClipboardBlocked(en.clickfix, {
      locale: 'en',
      url: 'https://example.invalid/',
      armDelayMs: 0,
    });
    button("I'm sure it's safe, allow once")?.click(); // untrusted
    expect(document.querySelector('paste-warden-overlay')).not.toBeNull();
    button('Keep blocked')?.click();
    await expect(result).resolves.toBe('keep-blocked');
  });

  it('arms "allow once" after a delay', () => {
    vi.useFakeTimers();
    showClipboardBlocked(en.clickfix, {
      locale: 'en',
      url: 'https://example.invalid/',
      armDelayMs: 600,
    });
    const allow = button("I'm sure it's safe, allow once") as HTMLButtonElement;
    expect(allow.disabled).toBe(true);
    vi.advanceTimersByTime(600);
    expect(allow.disabled).toBe(false);
  });

  it('never parses report text as HTML', () => {
    const evil = structuredClone(zh.clickfix);
    evil.command.reasons = [{ id: 'x', text: '<img src=x onerror=alert(1)>' }];
    // An engine never emits this kind; the cast simulates a hostile or corrupted report.
    const kind = '<b>k</b>' as TraceKind;
    evil.command.trace = [{ kind, text: '<i>t</i>', preview: '<script>1</script>' }];
    showClipboardBlocked(evil, { ...test, url: 'javascript:<svg onload=alert(1)>' });
    expect(shadow?.querySelector('img, script, .bdy b, i, [onload], [onerror]')).toBeNull();
    expect(q('.lv code')?.textContent).toBe('<b>k</b>');
    expect(q('.bdy ul li')?.textContent).toBe('<img src=x onerror=alert(1)>');
  });

  it('opening a second overlay settles the first with its safe choice', async () => {
    const first = showClipboardBlocked(en.clickfix, { ...test, url: 'https://example.invalid/' });
    const second = showPasteConfirm(en.secrets, test);
    await expect(first).resolves.toBe('keep-blocked');
    expect(document.querySelectorAll('paste-warden-overlay')).toHaveLength(1);
    press('Escape');
    await expect(second).resolves.toBe('cancel');
  });
});

describe('showPasteConfirm', () => {
  it('lists masked secrets and focuses "paste masked"', async () => {
    const result = showPasteConfirm(zh.secrets, { ...test, locale: 'zh-TW' });
    expect(q('#pw-d')?.textContent).toBe('偵測到 3 個機密。建議貼上遮罩版。');
    const codes = [...(shadow?.querySelectorAll('.sec code') ?? [])].map((c) => c.textContent);
    expect(codes).toEqual(['A1*******9', '4111 **** **** 1111', 'sk-p…****…Q3x']);
    expect(shadow?.activeElement?.textContent).toBe('貼上遮罩版');
    press('Enter');
    await expect(result).resolves.toBe('masked');
  });

  it('Enter means masked even when "original" has focus', async () => {
    const result = showPasteConfirm(en.secrets, { ...test, locale: 'en' });
    button('Paste original')?.focus();
    expect(shadow?.activeElement?.textContent).toBe('Paste original');
    const event = press('Enter');
    expect(event.defaultPrevented).toBe(true);
    await expect(result).resolves.toBe('masked');
  });

  it('Esc cancels; clicking original resolves original', async () => {
    const a = showPasteConfirm(en.secrets, { ...test, locale: 'en' });
    press('Escape');
    await expect(a).resolves.toBe('cancel');
    const b = showPasteConfirm(en.secrets, { ...test, locale: 'en' });
    button('Paste original')?.click();
    await expect(b).resolves.toBe('original');
    const c = showPasteConfirm(en.secrets, { ...test, locale: 'en' });
    button('Cancel')?.click();
    await expect(c).resolves.toBe('cancel');
  });

  it('traps Tab focus inside the dialog', () => {
    showPasteConfirm(en.secrets, { ...test, locale: 'en' });
    const order = ['Paste masked', 'Cancel', 'Paste original', 'Paste masked'];
    for (const name of order) {
      expect(shadow?.activeElement?.textContent).toBe(name);
      press('Tab');
    }
    press('Tab', { shiftKey: true });
    press('Tab', { shiftKey: true });
    expect(shadow?.activeElement?.textContent).toBe('Paste original');
  });

  it('keeps keystrokes from reaching the page and restores focus afterwards', async () => {
    const input = document.createElement('textarea');
    document.body.append(input);
    input.focus();
    const pageKeys = vi.fn();
    window.addEventListener('keydown', pageKeys);
    const result = showPasteConfirm(en.secrets, { ...test, locale: 'en' });
    press('a');
    expect(pageKeys).not.toHaveBeenCalled();
    press('Escape');
    await result;
    expect(document.activeElement).toBe(input);
    window.removeEventListener('keydown', pageKeys);
  });
});

describe('strings and theme', () => {
  it('follows the OS language and colour scheme, not the page', () => {
    expect(systemLocale(['zh-Hant-TW'])).toBe('zh-TW');
    expect(systemLocale(['de-DE'])).toBe('en');
    expect(CSS).toContain('@media (prefers-color-scheme:dark)');
    expect(CSS).toContain('prefers-reduced-motion');
  });

  it('parses the overlay ftl files with identical ids in both locales', () => {
    const files = import.meta.glob('../../../locales/*/ui-overlay.ftl', {
      query: '?raw',
      import: 'default',
      eager: true,
    }) as Record<string, string>;
    const parsed = Object.entries(files).map(([path, text]) => [path, parseFtl(text)] as const);
    expect(parsed).toHaveLength(2);
    const [a, b] = parsed.map(([, s]) => Object.keys(s).sort());
    expect(a).toEqual(b);
    expect(a?.length).toBeGreaterThan(15);
    for (const [, s] of parsed)
      for (const v of Object.values(s)) expect(v.length).toBeGreaterThan(0);
  });
});
