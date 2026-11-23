// #27：通用包與國家包、上下文關鍵字、包的選擇（與 C# 的 SecretPacksTests 相同的樣本）。
// 樣本都是假資料：官方公布的範例號碼，或在執行時用演算法補上檢查碼的號碼。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  findSecrets, maskSecret, maskText, isValidIban, isValidChinaResidentId, isValidMyNumber, isValidHongKongId,
  isValidSingaporeNric, packsForLocales, countryOf, COUNTRIES, DEFAULT_PACKS, MAX_SCAN_LENGTH,
} from '../lib/secrets.js';
import { RULES, scanRule, asciiView, compileRules } from '../lib/rules.js';

const here = dirname(fileURLToPath(import.meta.url));
const ALL = packsForLocales(COUNTRIES.map((c) => `xx-${c}`));
const packs = (...countries) => new Set(['universal', ...countries]);
const US = packsForLocales(['en-US']);
const find = (text, p) => findSecrets(text, { packs: p });
const none = (text, p) => assert.deepEqual(find(text, p).map((f) => `${f.label} ${maskSecret(f)}`), [], text);
const single = (text, p) => {
  const f = find(text, p);
  assert.equal(f.length, 1, `${text}: ${f.map((x) => x.label)}`);
  return f[0];
};

// ---------- 執行時補檢查碼（跟 pii.js 分開實作） ----------

function iban(country, bban) {
  let mod = 0;
  for (const c of bban + country + '00') mod = /[0-9]/.test(c) ? (mod * 10 + Number(c)) % 97 : (mod * 100 + c.charCodeAt(0) - 55) % 97;
  return `${country}${String(98 - mod).padStart(2, '0')}${bban}`;
}

function chinaId(first17) {
  const w = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
  const sum = [...first17].reduce((a, c, i) => a + Number(c) * w[i], 0);
  return first17 + '10X98765432'[sum % 11];
}

function myNumber(first11) {
  let sum = 0;
  for (let n = 1; n <= 11; n++) sum += Number(first11[11 - n]) * (n <= 6 ? n + 1 : n - 5);
  const r = sum % 11;
  return first11 + (r <= 1 ? 0 : 11 - r);
}

// ---------- 通用包 ----------

test('IBAN：官方範例與執行時產生的號碼，不管地區都開', () => {
  for (const [value, masked] of [
    ['DE89 3704 0044 0532 0130 00', 'DE89********3000'], ['DE89370400440532013000', 'DE89********3000'],
    ['GB82 WEST 1234 5698 7654 32', 'GB82********5432'],
  ]) {
    const text = `請匯款到 ${value}，謝謝`;
    const f = single(text, US);
    assert.equal(f.type, 'bank-account');
    assert.equal(maskSecret(f), masked);
    assert.equal(text.slice(f.start, f.end), value);
  }
  for (const [c, b] of [['NL', 'ABNA0417164300'], ['FR', '20041010050500013M02606'], ['NO', '86011117947'], ['CH', '00762011623852957']]) {
    const v = iban(c, b);
    assert.ok(isValidIban(v), v);
    assert.equal(single(`IBAN: ${v}`, ALL).type, 'bank-account');
  }
});

test('IBAN：不該命中', () => {
  for (const t of ['DE88 3704 0044 0532 0130 00', 'ZZ89 3704 0044 0532 0130 00', 'DE89 3704 0044 0532 0130 0',
    'de89 3704 0044 0532 0130 00', 'XDE89370400440532013000', 'DE89 3704  0044 0532 0130 00']) none(t, ALL);
});

test('國際電話：要以 + 開頭、國碼和長度合理', () => {
  for (const [phone, masked] of [
    ['+1 202-555-0123', '+12******123'], ['+1 (202) 555-0123', '+12******123'], ['+44 20 7946 0958', '+44*******958'],
    ['+61 491 570 156', '+61******156'], ['+81 3-0000-0000', '+81******000'], ['+852 0000 0000', '+85******000'],
  ]) {
    const text = `Call me at ${phone}.`;
    const f = single(text, US);
    assert.equal(f.type, 'phone-number');
    assert.equal(maskSecret(f), masked);
    assert.equal(text.slice(f.start, f.end), phone);
  }
  for (const t of ['202-555-0123', '(202) 555-0123', '+1 123 456 7890', '+1 202 555 01234', '+999 1234 5678', '+0800',
    'UTC+08:00 2024-01-15', '+12', 'x+12025550123', '+1202555012345678', '得分 +5 1234', 'version 1.0.0+20240115']) none(t, ALL);
});

test('台灣手機優先於國際電話；沒開台灣包時用國際電話提醒', () => {
  const f = single('+886 912-345-678', DEFAULT_PACKS);
  assert.equal(f.type, 'mobile-phone');
  assert.equal(maskSecret(f), '091****678');
  assert.equal(single('+886 912-345-678', US).type, 'phone-number');
});

// ---------- 國家包 ----------

test('中國居民身分證', () => {
  assert.ok(isValidChinaResidentId('11010519491231002X')); // GB 11643-1999 的範例
  const f = single('身份证号：11010519491231002X', packs('CN'));
  assert.equal(f.type, 'national-id');
  assert.equal(maskSecret(f), '110********02X');
  assert.equal(single(`${chinaId('44030420000101123')} 張三`, packs('CN')).type, 'national-id');
  assert.equal(single('110105 19491231 002x', packs('CN')).type, 'national-id');
  for (const t of ['110105194912310021', '911105194912310021', '1110105194912310021', chinaId('11010519490230002')]) none(t, ALL);
  none('11010519491231002X', DEFAULT_PACKS);
});

test('個人番號要有關鍵字', () => {
  assert.ok(isValidMyNumber('123456789018'));
  const jp = packs('JP');
  const f = single('マイナンバー：1234 5678 9018', jp);
  assert.equal(f.type, 'national-id');
  assert.equal(maskSecret(f), '********9018');
  single('個人番号 1234-5678-9018', jp);
  single(`My Number: ${myNumber('98765432109')}`, jp);
  for (const t of ['追跡番号 1234 5678 9018', '123456789018', 'マイナンバー：1234 5678 9017']) none(t, jp);
});

test('住民登錄番號要有關鍵字', () => {
  const kr = packs('KR');
  const f = single('주민등록번호: 900101-1234567', kr);
  assert.equal(f.type, 'national-id');
  assert.equal(maskSecret(f), '********567');
  single('RRN 9001011234567', kr);
  for (const t of ['900101-1234567', '주민등록번호: 901301-1234567', '주민등록번호: 900101-9234567']) none(t, kr);
});

test('香港身分證：括號不需要關鍵字，沒括號要有', () => {
  const hk = packs('HK');
  assert.ok(isValidHongKongId('A1234563'));
  const f = single('身份證 A123456(3)', hk);
  assert.equal(f.type, 'national-id');
  assert.equal(maskSecret(f), 'A*****63');
  single('A123456(3)', hk);
  single('HKID: A1234563', hk);
  const two = [...'0123456789A'].map((c) => `XA987654${c}`).find(isValidHongKongId);
  single(`HKID ${two}`, hk);
  const checkA = Array.from({ length: 900 }, (_, i) => `B${100000 + i}A`).find(isValidHongKongId);
  single(`${checkA.slice(0, -1)}(A)`, hk);
  for (const t of ['A1234563', 'A123456(4)', 'XA123456(3)A']) none(t, hk);
});

test('新加坡 NRIC／FIN', () => {
  for (const [id, type] of [['S1234567D', 'national-id'], ['T1234567J', 'national-id'], ['F1234567N', 'resident-certificate'],
    ['G1234567X', 'resident-certificate'], ['M1234567K', 'resident-certificate']]) {
    assert.ok(isValidSingaporeNric(id), id);
    const f = single(`NRIC/FIN: ${id}`, packs('SG'));
    assert.equal(f.type, type);
    assert.equal(maskSecret(f), `${id[0]}******${id.slice(-2)}`);
  }
  for (const t of ['S1234567A', 'A1234567D', 'S1234567DX', 's1234567d']) none(t, packs('SG'));
});

test('SSN 要有關鍵字，排除不會發的範圍', () => {
  for (const t of ['SSN: 078-05-1120', 'Social Security Number 219 09 9999', 'ssn=078051120', '078-05-1120 (SSN)',
    'Social Security\n078-05-1120', 'ＳＳＮ：０７８－０５－１１２０', 'sSn 078-05-1120']) {
    const f = single(t, US);
    assert.equal(f.type, 'national-id', t);
    const digits = t.slice(f.start, f.end).replace(/[^0-9０-９]/g, '');
    assert.equal(maskSecret(f).slice(0, 5), '*****');
    assert.equal(digits.length, 9);
  }
  for (const t of ['078-05-1120', 'Order 078-05-1120', 'SSN: 000-12-3456', 'SSN: 666-12-3456', 'SSN: 900-12-3456',
    'SSN: 123-00-4567', 'SSN: 123-45-0000', 'SSN: 123-45 6789', 'Bar Assn. 078-05-1120',
    `SSN is required.${'\n'.repeat(31)}Call 078-05-1120`]) none(t, US);
});

test('統編：關鍵字在單字裡不算，表格換行算', () => {
  none('private 12345675', DEFAULT_PACKS);
  single('VAT 12345675', DEFAULT_PACKS);
  single('統一編號\n12345675', DEFAULT_PACKS);
});

test('舊式居留證（第 2 碼 A–D）插件也偵測（#27 以前只有桌面版）', () => {
  const f = single('ARC: AB12345677', DEFAULT_PACKS);
  assert.equal(f.type, 'resident-certificate');
  assert.equal(f.label, '居留證號');
});

// ---------- 包的選擇 ----------

test('地區對應國家包（與 C# 相同）', () => {
  for (const [l, p] of [['TW', 'TW'], ['zh-TW', 'TW'], ['zh-Hant-TW', 'TW'], ['en-US', 'US'], ['US', 'US'], ['ja-JP', 'JP'],
    ['ja', 'JP'], ['ko', 'KR'], ['zh_CN', 'CN'], ['zh-Hant-HK', 'HK'], ['en-SG', 'SG'], ['en', null], ['fr-FR', null],
    ['zh', null], ['', null], [undefined, null]]) assert.equal(countryOf(l), p, String(l));
  assert.deepEqual(COUNTRIES, ['CN', 'HK', 'JP', 'KR', 'SG', 'TW', 'US']);
  assert.deepEqual([...packsForLocales(['zh-TW', 'en-US', 'en'])], ['universal', 'TW', 'US']);
  assert.deepEqual([...packsForLocales([])], ['universal']);
});

test('地區是美國時不偵測台灣身分證，通用包照常', () => {
  none('身分證 A123456789', US);
  assert.equal(single('4111 1111 1111 1111', US).type, 'credit-card');
  assert.equal(single('身分證 A123456789', packsForLocales(['zh-TW'])).type, 'national-id');
});

test('maskText 用跟 C# 一樣的遮罩', () => {
  assert.equal(maskText('IBAN DE89 3704 0044 0532 0130 00, SSN 078-05-1120', findSecrets('IBAN DE89 3704 0044 0532 0130 00, SSN 078-05-1120', { packs: US })),
    'IBAN DE89********3000, SSN *****1120');
});

test('規則檔的新欄位格式錯誤會報錯', () => {
  const base = { format: 1, name: 'bad', priority: 1 };
  for (const rule of [
    { regex: 'a', finder: 'card-groups' }, {}, { finder: 'nope' },
    { regex: 'a', context: { keywords: ['SSN'], before: 5 } }, { regex: 'a', context: { keywords: ['ssn'], before: 40 } },
    { regex: 'a', context: { keywords: ['ssn'] } }, { regex: 'a', mask: { canonical: 'nope' } },
  ]) {
    assert.throws(() => compileRules([{ ...base, rules: [{ id: 'x', kind: 'national-id', label: 'x', ...rule }] }]), JSON.stringify(rule));
  }
  assert.throws(() => compileRules([{ ...base, pack: 'tw', rules: [] }]));
});

// ---------- 誤報 ----------

test('所有包都開時的誤報樣本（與 C# 相同）', () => {
  for (const t of [
    '2024-01-15 2024-02-16 2024-03-17 2024-04-18', '會議日期：2023/11/22、2023/11/23、2023.11.24',
    '20240115123045 20240115123046', '訂單 20240115-0001 20240115-0002 20240115-0003',
    'Order #1234 5678 9012, tracking 1Z999AA10123456784', '追跡番号 1234-5678-9018',
    '電話 202-555-0123、02-2555-6666、(02)25556666', '123e4567-e89b-12d3-a456-426614174000',
    '9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08', 'DE89A1B2C3D4E5F6A7B8C9D0',
    'SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB0ZXN0Lg==', '版本 1.2.3.4，下一版 4.1.11.1111，semver 1.0.0+20240115',
    '192.168.100.200 10.0.0.1 172.16.254.1 +1.5%', 'Part no. S1234567A, SKU A1234563, model AB123456(7)',
    '價格 +5 1234、溫度 +12.5、時區 UTC+0800', '身分證 A123456788（檢查碼錯）', '110105194912310021 是一個 18 位數',
    'ISBN 978-0-306-40615-7 ISSN 0317-8471', 'a1b2c3d4e5f60718293a4b5c6d7e8f9012345678 commit',
  ]) none(t, ALL);
  const fixture = JSON.parse(readFileSync(join(here, '..', '..', 'tests', 'fixtures', 'secret-false-positives.json'), 'utf8'));
  for (const s of fixture.samples) assert.deepEqual(find(s.text, ALL).map((f) => f.label), [], s.name);
});

// ---------- 效能 ----------

const fill = (unit, n) => unit.repeat(Math.ceil(n / unit.length)).slice(0, n);
const pathological = (n) => [
  ['數字', fill('1', n)], ['單碼數字組', fill('1 ', n)], ['+1 ', fill('+1 ', n)], ['+ 加 15 碼', fill('+123456789012345 ', n)],
  ['字母數字', fill('A1', n)], ['IBAN 前綴', fill('DE89 ', n)], ['大寫英數', fill('DE8937040044', n)], ['括號', fill('A123456(', n)],
  ['SSN 關鍵字', fill('SSN 078-05-1120 ', n)], ['マイナンバー', fill('マイナンバー 1234 5678 9018 ', n)],
  ['주민등록번호', fill('주민등록번호 900101-1234567 ', n)], ['統編', fill('統編 12345675 ', n)],
  ['關鍵字沒有號碼', fill('ssn マイナンバー 주민번호 hkid 統編 ', n)], ['身分證', fill('A123456789 ', n)],
];

test('個資規則在 1 Mi 病態輸入上都是線性時間', () => {
  let worst = [0, '', ''];
  const inputs = pathological(1 << 20);
  for (const r of RULES.filter((x) => x.type !== 'api-key')) {
    for (const [name, text] of inputs) {
      const ascii = asciiView(text);
      const t = performance.now();
      for (const _ of scanRule(r, ascii, text)); // eslint-disable-line no-unused-vars
      const ms = performance.now() - t;
      if (ms > worst[0]) worst = [ms, r.id, name];
    }
  }
  console.log(`個資規則最慢 ${worst[0].toFixed(0)} ms（${worst[1]}，${worst[2]}）`);
  assert.ok(worst[0] < 1000, `${worst[1]} took ${worst[0]} ms`);
});

test('所有包都開時 1 Mi 也不會卡住', () => {
  let worst = 0;
  for (const [name, text] of pathological(MAX_SCAN_LENGTH)) {
    const t = performance.now();
    const found = find(text, ALL);
    const ms = performance.now() - t;
    worst = Math.max(worst, ms);
    console.log(`${name}: ${text.length} 字，${found.length} 筆，${ms.toFixed(0)} ms`);
    assert.ok(ms < 3000, `${name} took ${ms} ms`);
  }
  console.log(`最慢 ${worst.toFixed(0)} ms`);
});
