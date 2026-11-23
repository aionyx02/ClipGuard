#!/usr/bin/env node
// 把共用規則檔 rules/*.json 轉成插件用的 extension/lib/rules.generated.js。
//
// 插件執行時不能讀 extension/ 以外的檔案，也不連網，所以規則要先複製進來。改了 rules/ 之後執行：
//   node tools/build-extension-rules.mjs
// extension/test/rules.test.js 會檢查產生的檔案是不是最新的（忘了執行就會失敗）。

import { readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
export const RULES_DIR = join(root, 'rules');
export const OUTPUT = join(root, 'extension', 'lib', 'rules.generated.js');

// 只留比對需要的欄位；說明、略過清單、來源資訊留在 rules/ 裡。
const DROP = new Set(['description', 'skipped', 'notes']);

export function render(dir = RULES_DIR) {
  const files = readdirSync(dir).filter((f) => f.endsWith('.json')).sort();
  const parts = files.map((f) => {
    const data = JSON.parse(readFileSync(join(dir, f), 'utf8'));
    const slim = JSON.stringify(data, (key, value) => {
      if (DROP.has(key)) return undefined;
      return value;
    });
    return `  // rules/${f}\n  ${slim},`;
  });
  return [
    '// 由 tools/build-extension-rules.mjs 從 rules/*.json 產生，不要手動修改。',
    '// rules/gitleaks.json 轉換自 gitleaks（MIT License，Copyright (c) 2019 Zachary Rice），見 THIRD_PARTY_NOTICES.md。',
    'export default [',
    ...parts,
    '];',
    '',
  ].join('\n');
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  writeFileSync(OUTPUT, render());
  console.log(`已產生 ${OUTPUT}`);
}
