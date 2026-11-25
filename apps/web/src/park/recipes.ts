/**
 * Park UI recipes ported to Tailwind class strings (https://park-ui.com/docs/components/button,
 * …/badge, …/card). Same variant names as Park: solid, surface, subtle, outline, plain.
 */

type Variant = 'solid' | 'surface' | 'subtle' | 'outline' | 'plain';
type Size = 'sm' | 'md' | 'lg';

const BUTTON_BASE =
  'inline-flex shrink-0 items-center justify-center gap-2 whitespace-nowrap rounded-l2 font-semibold transition-colors duration-150 motion-reduce:transition-none focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus aria-disabled:cursor-not-allowed aria-disabled:opacity-50';

const BUTTON_VARIANT: Record<Variant, string> = {
  solid: 'bg-solid text-solid-fg hover:bg-solid-hover',
  surface:
    'border border-border-default bg-bg-default text-fg shadow-xs hover:bg-bg-subtle active:bg-bg-muted',
  subtle: 'bg-gray-a3 text-fg hover:bg-gray-a4 active:bg-gray-a5',
  outline: 'border border-border-default text-fg hover:bg-gray-a2 active:bg-gray-a3',
  plain: 'text-fg-muted hover:bg-gray-a3 hover:text-fg',
};

const BUTTON_SIZE: Record<Size, string> = {
  sm: 'min-h-9 px-3 text-sm',
  md: 'min-h-10 px-4 text-sm',
  lg: 'min-h-11 px-5 text-[0.9375rem]',
};

export function button({
  variant = 'solid',
  size = 'md',
}: {
  variant?: Variant;
  size?: Size;
} = {}) {
  return `${BUTTON_BASE} ${BUTTON_VARIANT[variant]} ${BUTTON_SIZE[size]}`;
}

const BADGE_VARIANT: Record<'subtle' | 'outline', string> = {
  subtle: 'bg-gray-a3 text-fg-muted',
  outline: 'border border-border-default text-fg-muted',
};

export function badge(variant: keyof typeof BADGE_VARIANT = 'subtle') {
  return `inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium ${BADGE_VARIANT[variant]}`;
}

/** Park card: bg.default, l3 radius, a hairline border and the xs shadow. */
export const CARD = 'rounded-l3 border border-border-default bg-bg-default shadow-xs';

/** Icon tile used in feature cards. */
export const ICON_TILE =
  'inline-flex size-10 items-center justify-center rounded-l2 border border-border-muted bg-bg-subtle text-accent';
