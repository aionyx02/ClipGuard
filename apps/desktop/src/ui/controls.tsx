import { type ButtonHTMLAttributes, forwardRef, type ReactNode, useId } from 'react';

export function cx(...parts: Array<string | false | null | undefined>): string {
  return parts.filter(Boolean).join(' ');
}

export function Section({
  title,
  description,
  children,
  id,
}: {
  title: string;
  description?: ReactNode;
  children: ReactNode;
  id?: string;
}) {
  const headingId = useId();
  return (
    <section
      id={id}
      aria-labelledby={headingId}
      className="rounded-[var(--radius-card)] border border-line bg-surface p-5 shadow-[var(--shadow-card)]"
    >
      <h2 id={headingId} className="text-base font-semibold">
        {title}
      </h2>
      {description ? <div className="mt-1 text-sm text-fg-muted">{description}</div> : null}
      <div className="mt-3">{children}</div>
    </section>
  );
}

type Variant = 'primary' | 'secondary' | 'danger' | 'ghost';

const VARIANTS: Record<Variant, string> = {
  primary: 'bg-accent text-accent-fg hover:opacity-90',
  secondary: 'border border-line bg-surface-2 text-fg hover:bg-surface',
  danger: 'border border-quarantine-line bg-quarantine-bg text-quarantine hover:opacity-90',
  ghost: 'text-fg-muted hover:bg-surface-2',
};

export const Button = forwardRef<
  HTMLButtonElement,
  ButtonHTMLAttributes<HTMLButtonElement> & { variant?: Variant }
>(function Button({ variant = 'secondary', className, type = 'button', ...rest }, ref) {
  return (
    <button
      ref={ref}
      type={type}
      className={cx(
        'rounded-lg px-4 py-1.5 text-sm font-semibold disabled:cursor-not-allowed disabled:opacity-50',
        VARIANTS[variant],
        className,
      )}
      {...rest}
    />
  );
});

export interface SwitchProps {
  label: string;
  description?: ReactNode;
  checked: boolean;
  disabled?: boolean;
  onChange: (checked: boolean) => void;
}

/** A labelled on/off switch (a native checkbox with role="switch"). */
export function Switch({ label, description, checked, disabled, onChange }: SwitchProps) {
  const id = useId();
  return (
    <div className="flex items-start justify-between gap-4 py-2.5">
      <div className="min-w-0">
        <label htmlFor={id} className="block text-sm font-medium text-fg">
          {label}
        </label>
        {description ? (
          <div id={`${id}-d`} className="mt-0.5 text-xs leading-relaxed text-fg-muted">
            {description}
          </div>
        ) : null}
      </div>
      <span className="relative mt-0.5 inline-flex shrink-0">
        <input
          id={id}
          type="checkbox"
          role="switch"
          aria-checked={checked}
          aria-describedby={description ? `${id}-d` : undefined}
          checked={checked}
          disabled={disabled}
          onChange={(e) => onChange(e.target.checked)}
          className="peer h-6 w-11 cursor-pointer appearance-none rounded-full border border-line bg-surface-2 transition-colors checked:border-accent checked:bg-accent disabled:cursor-not-allowed disabled:opacity-50"
        />
        <span
          aria-hidden="true"
          className="pointer-events-none absolute top-1 left-1 size-4 rounded-full bg-fg-muted shadow transition-transform peer-checked:translate-x-5 peer-checked:bg-accent-fg"
        />
      </span>
    </div>
  );
}
