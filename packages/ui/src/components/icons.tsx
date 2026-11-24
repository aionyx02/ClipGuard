import type { Action } from '../report';

export function cx(...parts: Array<string | false | null | undefined>): string {
  return parts.filter(Boolean).join(' ');
}

interface IconProps {
  className?: string;
}

/** The PasteWarden mark (shield + clipboard clip), simplified from assets/logo.svg. */
export function ShieldMark({ className }: IconProps) {
  return (
    <svg viewBox="0 0 128 128" className={className} aria-hidden="true" focusable="false">
      <defs>
        <linearGradient id="pw-mark" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#3B82F6" />
          <stop offset="1" stopColor="#0D9488" />
        </linearGradient>
      </defs>
      <path
        d="M30 24H98a8 8 0 0 1 8 8V64c0 26-17 42-42 54C39 106 22 90 22 64V32a8 8 0 0 1 8-8Z"
        fill="url(#pw-mark)"
      />
      <rect x="42" y="12" width="44" height="22" rx="7" fill="#E2E8F0" />
      <rect x="55" y="17" width="18" height="7" rx="3.5" fill="#1E3A8A" />
      <path
        d="M43 68l15 15 28-31"
        fill="none"
        stroke="#fff"
        strokeWidth="11"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

/** Verdict glyph: a stop octagon, a warning triangle, or a check. Shape carries meaning without colour. */
export function ActionIcon({ action, className }: IconProps & { action: Action }) {
  return (
    <svg
      viewBox="0 0 24 24"
      className={className}
      aria-hidden="true"
      focusable="false"
      fill="none"
      stroke="currentColor"
      strokeWidth={2}
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      {action === 'quarantine' ? (
        <>
          <path d="M8.2 2.5h7.6l5.7 5.7v7.6l-5.7 5.7H8.2l-5.7-5.7V8.2z" />
          <path d="M9 9l6 6M15 9l-6 6" />
        </>
      ) : action === 'warn' ? (
        <>
          <path d="M12 3.5 2.5 20h19z" />
          <path d="M12 10v4.5M12 17.5v.01" />
        </>
      ) : (
        <>
          <path d="M12 2.8 4 6v6c0 4.6 3.4 8 8 9.2 4.6-1.2 8-4.6 8-9.2V6z" />
          <path d="m8.5 12 2.5 2.5 4.5-5" />
        </>
      )}
    </svg>
  );
}

/** Tailwind classes per verdict tone. Listed literally so Tailwind's scanner sees them. */
export const TONE: Record<
  Action,
  { text: string; bg: string; border: string; fill: string; ring: string }
> = {
  quarantine: {
    text: 'text-quarantine',
    bg: 'bg-quarantine-bg',
    border: 'border-quarantine-line',
    fill: 'bg-quarantine',
    ring: 'ring-quarantine-line',
  },
  warn: {
    text: 'text-warn',
    bg: 'bg-warn-bg',
    border: 'border-warn-line',
    fill: 'bg-warn',
    ring: 'ring-warn-line',
  },
  allow: {
    text: 'text-allow',
    bg: 'bg-allow-bg',
    border: 'border-allow-line',
    fill: 'bg-allow',
    ring: 'ring-allow-line',
  },
};
