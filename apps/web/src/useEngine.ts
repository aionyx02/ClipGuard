import { useEffect, useState } from 'react';
import { type LoadedEngine, loadEngine } from './engine';

export type EngineState =
  | { status: 'loading' }
  | { status: 'ready'; engine: LoadedEngine }
  | { status: 'error' };

/** Starts loading the engine after the first render; the page is usable (skeleton) meanwhile. */
export function useEngine(load: () => Promise<LoadedEngine> = loadEngine): EngineState {
  const [state, setState] = useState<EngineState>({ status: 'loading' });
  useEffect(() => {
    let alive = true;
    load().then(
      (engine) => alive && setState({ status: 'ready', engine }),
      () => alive && setState({ status: 'error' }),
    );
    return () => {
      alive = false;
    };
  }, [load]);
  return state;
}
