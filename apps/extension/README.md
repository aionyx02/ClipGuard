# PasteWarden browser extension and userscript

Chrome / Edge (MV3) and Firefox (MV3) extension built with [WXT](https://wxt.dev), plus the
userscript in `../userscript`. Spec: `docs/plan/phase-3.md` §3.2–§3.4, §3.7; architecture from
`docs/spikes/s2-wasm-csp.md`.

## Build

```sh
pnpm install
pnpm --filter @paste-warden/core build        # the engine (Rust → WASM + wasm2js); needs wasm-bindgen-cli
pnpm --filter @paste-warden/extension build   # everything below
```

`dist/` then holds:

| File                               | What                                                                                        |
| ---------------------------------- | ------------------------------------------------------------------------------------------- |
| `paste-warden-chrome.zip`          | Chrome / Edge, MV3. Extract and "Load unpacked".                                            |
| `paste-warden-firefox.xpi`         | Firefox, MV3, **unsigned** (signing is Phase 6): `about:debugging` → Load Temporary Add-on. |
| `paste-warden-firefox-sources.zip` | Sources zip WXT makes for AMO review (Phase 6).                                             |
| `paste-warden.user.js`             | Userscript (built by `apps/userscript`, copied here).                                       |

Unpacked builds stay in `.output/chrome-mv3/` and `.output/firefox-mv3/`. Other commands:

```sh
pnpm --filter @paste-warden/extension dev            # WXT dev mode (Chrome)
pnpm --filter @paste-warden/extension dev:firefox
pnpm --filter @paste-warden/userscript build         # only the userscript → apps/userscript/dist/
pnpm --filter @paste-warden/extension lint           # Biome + tsc
pnpm --filter @paste-warden/extension test           # Vitest (needs the core build)
pnpm --filter @paste-warden/extension exec playwright install chromium firefox
pnpm --filter @paste-warden/extension e2e            # Playwright: Chromium + Firefox × 3 CSPs
pnpm --filter @paste-warden/userscript e2e
```

The e2e tests use Playwright's own browsers with temporary profiles only, and read the clipboard
back inside the browser (a real paste into the test page). On macOS, `e2e/global-setup.ts` keeps an
in-memory copy of the system pasteboard's text and restores it if a run changed it.

## How it works

```
page JS ──writeText / write / setData / items.add / execCommand('copy')──┐
                                                                          ▼
MAIN world  src/lib/hook.ts   ── sync CustomEvent, random name per page ──▶ isolated world
(entrypoints/hook.content.ts)     sends: {via, text}                      src/lib/guard.ts (+ WASM engine)
                                  gets:  allow | block + notice text       overlay / notice / paste confirm
                                                                          │ runtime messages
                                                                          ▼
                                                     background: settings defaults, recent blocks,
                                                     sub-frame → top-frame dialogs, clipboard fallback
                                                     (Chrome offscreen execCommand / Firefox background)
```

- **Clipboard writes**: `quarantine` → the page's text is replaced by a harmless notice
  (`ui-ext-clipboard-notice`) and the overlay's blocked dialog opens in the top frame (source URL,
  reasons, onion view, "allow once"). `warn` → written unchanged, non-blocking notice.
  Page writes are analyzed with `detect_secrets: false`: a site's own "copy API key" button is not
  an attack; secrets are guarded on paste.
- **Paste**: only when the pasted text contains secrets; Enter = masked, Esc = cancel, original only
  by an explicit (trusted) click. Password fields and non-editable targets are skipped. The page's
  own paste handlers never see the intercepted text.
- **Pastejacking**: `src/lib/pastejack.ts` (port of `crates/core/src/pastejack`, same
  `rules/pastejack/*.json`, tested against `corpus/cases/pastejack*.jsonl`). Copy-event writes
  compare with the selection; async writes only within 2 s of a copy with no input in between.
- **Channel (T17)**: the handshake happens at `document_start` before any page script; MAIN keeps
  its own copies of the natives; if the channel is paired but a request goes unanswered, MAIN
  writes the notice (fail closed).
- **Frames (T18)**: content scripts in all frames (`all_frames`, `match_about_blank`, Chrome
  `match_origin_as_fallback`); same-origin children are also hooked when the page touches
  `contentWindow` / `contentDocument` or inserts an iframe.
- **Engine**: WASM in the isolated content script (`engine/paste_warden_bg.wasm`, web-accessible);
  if that ever fails, the wasm2js build is imported on demand from `engine/w2j/`.
- **Permissions**: `storage`, `clipboardWrite`, `offscreen` (Chrome only); no `tabs`, `history` or
  extra host permissions. Works with no desktop app installed.
- **Strings**: `locales/{zh-TW,en}/ui-extension.ftl` (`ui-ext-*`) and `pastejack.ftl`.

## Userscript

`apps/userscript` reuses `src/lib/*`. `@inject-into content`; the page hook is injected as an
inline `<script>` and pairs over the same channel. If the page CSP blocks it, the script hooks its
own world (enough when the manager runs it in the page) and retries with the page's nonce; the
engine falls back to wasm2js where WebAssembly is blocked. Settings live in `GM_setValue`; the
manager menu toggles protection and "pause on this site".
