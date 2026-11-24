/**
 * Overlay CSS. Lives inside a closed shadow root, so page styles cannot reach it and it cannot
 * leak out. Colours follow `prefers-color-scheme` (the OS / browser), never the page's theme.
 * Palette mirrors packages/ui/src/styles.css (ink navy, teal #5EEAD4, red / amber verdicts).
 */
export const CSS = `
:host{all:initial}
*{box-sizing:border-box}
.r{--bg:#fff;--bg2:#f5f7fa;--fg:#0b1220;--mu:#4a5b72;--ln:#d3dbe5;--ac:#0f766e;--acf:#fff;--q:#b42318;--qb:#fef1f0;--ql:#f4b8b2;--w:#935f00;--wb:#fff7e6;--wl:#f2cf85;--code:#0b1220;--codef:#e8edf3;
color-scheme:light;font:14px/1.5 Inter,"Noto Sans TC","PingFang TC","Microsoft JhengHei",system-ui,sans-serif;color:var(--fg)}
@media (prefers-color-scheme:dark){.r{--bg:#0f1a2b;--bg2:#142236;--fg:#e8edf3;--mu:#a9b6c6;--ln:#26364c;--ac:#5eead4;--acf:#0b1220;--q:#ff8a80;--qb:#2a1215;--ql:#6b2a2a;--w:#fbbf4d;--wb:#2a1f0b;--wl:#6b4f14;--code:#070c16;color-scheme:dark}.r .bd,.r dialog::backdrop{background:rgb(0 0 0/.6)}}
.bd{position:fixed;inset:0;background:rgb(7 12 22/.45)}
dialog{position:fixed;inset:0;margin:auto;height:fit-content;max-height:calc(100vh - 32px);overflow:auto;padding:0;border:1px solid var(--ql);border-radius:14px;background:var(--bg);color:var(--fg);width:min(560px,calc(100vw - 32px));max-height:none;box-shadow:0 24px 64px -16px rgb(0 0 0/.45)}
dialog::backdrop{background:rgb(7 12 22/.45)}
dialog.warn{border-color:var(--wl)}
.hd{display:flex;gap:12px;align-items:flex-start;padding:16px 20px;background:var(--qb);border-bottom:1px solid var(--ql);border-left:6px solid var(--q)}
.warn .hd{background:var(--wb);border-color:var(--wl);border-left-color:var(--w)}
.ic{flex:none;width:36px;height:36px;border-radius:50%;display:grid;place-items:center;background:var(--bg);color:var(--q);box-shadow:inset 0 0 0 1px var(--ql)}
.warn .ic{color:var(--w);box-shadow:inset 0 0 0 1px var(--wl)}
.ic svg{width:22px;height:22px}
.br{display:flex;align-items:center;gap:6px;font-size:12px;font-weight:600;color:var(--mu);letter-spacing:.02em}
.br b{color:var(--ac);font-weight:700}
h2{margin:2px 0 0;font-size:17px;line-height:1.35;font-weight:650;color:var(--q)}
.warn h2{color:var(--w)}
.rk{margin-left:auto;flex:none;font:600 12px/1 ui-monospace,Menlo,Consolas,monospace;padding:5px 8px;border-radius:999px;background:var(--bg);color:var(--q);box-shadow:inset 0 0 0 1px var(--ql)}
.bdy{padding:16px 20px 4px}
p{margin:0 0 12px}
.src{display:flex;gap:8px;align-items:baseline;font-size:13px;color:var(--mu);margin-bottom:12px}
.src code{color:var(--fg);word-break:break-all}
code,pre{font:12.5px/1.5 "JetBrains Mono",ui-monospace,Menlo,Consolas,monospace}
h3{font-size:13px;margin:0 0 6px;font-weight:650}
ul{margin:0 0 12px;padding:0 0 0 18px}
li{margin:2px 0}
.sec{list-style:none;padding:0;border:1px solid var(--ln);border-radius:10px;overflow:hidden}
.sec li{display:flex;justify-content:space-between;gap:12px;align-items:center;padding:8px 12px;margin:0;background:var(--bg2)}
.sec li+li{border-top:1px solid var(--ln)}
.sec code{background:var(--code);color:#99f6e4;padding:2px 8px;border-radius:6px}
details{border:1px solid var(--ln);border-radius:10px;margin:0 0 12px;background:var(--bg2)}
summary{cursor:pointer;padding:8px 12px;font-weight:600;font-size:13px}
summary:focus-visible,button:focus-visible{outline:2px solid var(--ac);outline-offset:2px}
ol{list-style:none;margin:0;padding:0 12px 12px}
ol li{margin:0;padding:6px 0 6px 10px;border-left:2px solid var(--ln)}
ol li:last-child{border-left-color:var(--q)}
.lv{font-size:12px;color:var(--mu)}
.lv code{color:var(--ac)}
pre{margin:4px 0 0;padding:6px 8px;border-radius:6px;background:var(--code);color:var(--codef);white-space:pre-wrap;word-break:break-all;max-height:8.5em;overflow:auto}
.ft{display:flex;flex-wrap:wrap;gap:8px;justify-content:flex-end;padding:12px 20px 16px}
.hint{flex:1 1 100%;font-size:12px;color:var(--mu);margin:0 0 4px}
button{font:inherit;font-weight:600;border-radius:9px;padding:8px 14px;cursor:pointer;border:1px solid var(--ln);background:var(--bg);color:var(--fg)}
button.pri{background:var(--ac);border-color:var(--ac);color:var(--acf)}
button.dan{color:var(--q);border-color:var(--ql)}
button:disabled{opacity:.45;cursor:not-allowed}
@media (prefers-reduced-motion:no-preference){dialog{animation:pw-in .18s ease-out}@keyframes pw-in{from{opacity:0;transform:translateY(-8px)}}}
`;
