import { useId } from 'react';

export interface SwitchProps {
  label: string;
  description?: string;
  checked: boolean;
  disabled?: boolean;
  onChange: (checked: boolean) => void;
}

/** A labelled on/off switch (a native checkbox with role="switch": keyboard and AT for free). */
export function Switch({ label, description, checked, disabled, onChange }: SwitchProps) {
  const id = useId();
  return (
    <div className="flex items-start justify-between gap-4 py-2.5">
      <div className="min-w-0">
        <label htmlFor={id} className="block text-sm font-medium text-fg">
          {label}
        </label>
        {description ? (
          <p id={`${id}-d`} className="mt-0.5 text-xs leading-relaxed text-fg-muted">
            {description}
          </p>
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
