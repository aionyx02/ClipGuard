// A fake Tauri backend: `@tauri-apps/api/{core,event,app}` are mocked in setup.ts to go
// through here. Tests set command handlers and emit events.
import { act } from '@testing-library/react';
import { vi } from 'vitest';

type Handler = (args: Record<string, unknown> | undefined) => unknown;
type Listener = (event: { event: string; id: number; payload: unknown }) => void;

export const handlers = new Map<string, Handler>();
const listeners = new Map<string, Set<Listener>>();

export const invoke = vi.fn(async (cmd: string, args?: Record<string, unknown>) => {
  const h = handlers.get(cmd);
  if (!h) return undefined;
  return h(args);
});

export async function listen(event: string, cb: Listener) {
  let set = listeners.get(event);
  if (!set) {
    set = new Set();
    listeners.set(event, set);
  }
  set.add(cb);
  return () => {
    set.delete(cb);
  };
}

/** Delivers an event to every listener, inside act(). */
export async function emit(event: string, payload: unknown) {
  await act(async () => {
    for (const cb of listeners.get(event) ?? []) cb({ event, id: 0, payload });
  });
}

export function resetTauri() {
  handlers.clear();
  listeners.clear();
  invoke.mockClear();
}

/** Commands called so far, with their arguments. */
export function calls(cmd: string): Array<Record<string, unknown> | undefined> {
  return invoke.mock.calls.filter(([c]) => c === cmd).map(([, a]) => a);
}
