// Chrome offscreen document (reason CLIPBOARD): writes text with execCommand('copy'), which works
// without focus or a user gesture here, unlike navigator.clipboard (S2). The text is cleared from
// the textarea right after.
import { browser } from 'wxt/browser';
import type { ToOffscreen } from '../../lib/messages';

const buffer = document.getElementById('buffer') as HTMLTextAreaElement;

browser.runtime.onMessage.addListener((raw: unknown) => {
  const msg = raw as ToOffscreen;
  if (
    msg?.target !== 'offscreen' ||
    msg.type !== 'offscreen-write' ||
    typeof msg.text !== 'string'
  ) {
    return undefined;
  }
  buffer.value = msg.text;
  buffer.select();
  let ok = false;
  try {
    ok = document.execCommand('copy');
  } finally {
    buffer.value = '';
  }
  return Promise.resolve(ok);
});
