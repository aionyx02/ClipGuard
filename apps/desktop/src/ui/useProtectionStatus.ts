import { useEffect, useState } from 'react';
import { events, ipc, type ProtectionStatus, subscribe } from '../lib/ipc';

/** §4.8.1: asks once, then follows `protection-status`. `null` until Rust answers. */
export function useProtectionStatus(): ProtectionStatus | null {
  const [status, setStatus] = useState<ProtectionStatus | null>(null);
  useEffect(() => {
    let live = true;
    let gotEvent = false;
    const stop = subscribe(() =>
      events.protectionStatus((s) => {
        gotEvent = true;
        if (live) setStatus(s);
      }),
    );
    ipc
      .getProtectionStatus()
      .then((s) => {
        // An event that arrived meanwhile is newer than this answer.
        if (live && !gotEvent) setStatus(s);
      })
      .catch(() => {});
    return () => {
      live = false;
      stop();
    };
  }, []);
  return status;
}
