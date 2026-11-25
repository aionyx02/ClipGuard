import { useT } from '@paste-warden/ui';
import type { CommandError } from '../lib/ipc';

/** A command error rendered through Fluent. Only message ids and their args reach the screen. */
export function ErrorText({ id, error }: { id: string; error: CommandError | null }) {
  const t = useT();
  if (!error) return null;
  return (
    <p id={id} role="alert" className="mt-1.5 text-xs text-quarantine">
      {t(error.messageId, error.args)}
    </p>
  );
}
