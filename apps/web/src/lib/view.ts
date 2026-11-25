// Two views on one static page: the home page and the playground at `#/play`. A hash route keeps
// GitHub Pages happy (no server rewrites) and the back button works. Any other hash (`#privacy`,
// `#download`) is an anchor on the home page.
import { useEffect, useState } from 'react';

export type View = 'home' | 'play';

export const PLAY_HASH = '#/play';

export function viewOf(hash: string): View {
  return hash === PLAY_HASH || hash.startsWith(`${PLAY_HASH}/`) ? 'play' : 'home';
}

export function useView(win: Window = window): View {
  const [view, setView] = useState<View>(() => viewOf(win.location.hash));
  useEffect(() => {
    const sync = () => {
      const next = viewOf(win.location.hash);
      setView(next);
      const anchor = win.location.hash.slice(1);
      // Wait for the view to render, then land at the top or on the requested section.
      requestAnimationFrame(() => {
        const target = next === 'home' && anchor ? win.document.getElementById(anchor) : null;
        if (target) target.scrollIntoView();
        else win.scrollTo(0, 0);
      });
    };
    win.addEventListener('hashchange', sync);
    return () => win.removeEventListener('hashchange', sync);
  }, [win]);
  return view;
}
