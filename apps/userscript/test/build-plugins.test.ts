// The userscript's build relies on the exact shape of @paste-warden/core's dist output: fail
// loudly here (not silently in the bundle) when that changes.
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { noNodeFsImport } from '../../extension/scripts/core-plugins.mjs';
import { staticCoreImports } from '../build-plugins';

const dist = resolve(process.cwd(), '../../packages/core-js/dist');

type Transform = (code: string, id: string) => { code: string } | null;
const transform = staticCoreImports().transform as unknown as Transform;
const dropFs = noNodeFsImport().transform as unknown as Transform;

describe('staticCoreImports', () => {
  it('turns backend.js dynamic imports into static ones (with noNodeFsImport: none left)', () => {
    const id = `${dist}/backend.js`;
    const withoutFs = dropFs(readFileSync(id, 'utf8'), id);
    expect(withoutFs).not.toBeNull();
    const out = transform(withoutFs?.code ?? '', id);
    expect(out).not.toBeNull();
    expect(out?.code).not.toMatch(/\bimport\(/);
    expect(out?.code).toContain("import * as __pwRaw from './wasm2js/paste_warden_raw.js'");
  });

  it('makes the wasm2js module lazy (no engine built at import time)', () => {
    const id = `${dist}/wasm2js/paste_warden_raw.js`;
    const out = transform(readFileSync(id, 'utf8'), id);
    expect(
      out?.code.trimEnd().endsWith('export function instantiate() { return asmFunc({}); }'),
    ).toBe(true);
    expect(out?.code).not.toContain('retasmFunc');
  });

  it('leaves other modules alone', () => {
    expect(transform('export const x = 1;', '/x/src/main.ts')).toBeNull();
  });
});
