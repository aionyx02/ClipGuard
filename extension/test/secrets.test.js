import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  isValidTaiwanId, isValidUbn, isValidLuhn, findSecrets, maskSecret, maskText, MAX_SCAN_LENGTH,
} from '../lib/secrets.js';

const types = (text) => findSecrets(text).map((f) => f.type);

// ---------- 身分證 ----------

test('身分證：合法號碼通過檢查碼', () => {
  assert.equal(isValidTaiwanId('A123456789'), true);
  assert.equal(isValidTaiwanId('B212345670'), true);
});

test('身分證：新式居留證（第二碼 8/9）同一套檢查碼', () => {
  assert.equal(isValidTaiwanId('A812345671'), true);
  assert.equal(isValidTaiwanId('F912345678'), true);
});

test('身分證：檢查碼錯、第二碼不合法、長度不對都不通過', () => {
  assert.equal(isValidTaiwanId('A123456788'), false);
  assert.equal(isValidTaiwanId('A323456789'), false);
  assert.equal(isValidTaiwanId('A12345678'), false);
});

test('身分證：在句子中找得到，小寫字母也算', () => {
  assert.deepEqual(types('我的身分證是 A123456789 喔'), ['tw-id']);
  assert.deepEqual(types('a123456789'), ['tw-id']);
});

test('身分證：檢查碼錯或黏在更長的英數字串裡不算', () => {
  assert.deepEqual(types('A123456788'), []);
  assert.deepEqual(types('XA123456789'), []);
  assert.deepEqual(types('A1234567890'), []);
});

// ---------- 統一編號 ----------

test('統編：舊規則（可被 10 整除）的號碼在新規則下仍合法', () => {
  assert.equal(isValidUbn('22099131'), true);
  assert.equal(isValidUbn('04595257'), true);
});

test('統編：2023 年起的新號碼（只可被 5 整除）合法', () => {
  // 總和 = 5，舊規則不通過、新規則通過。
  assert.equal(isValidUbn('10000004'), true);
  assert.equal(isValidUbn('10000010'), true);
});

test('統編：第 7 碼為 7 時，28 的 2+8=10 可取 1 或 0', () => {
  assert.equal(isValidUbn('10458575'), true); // 取 0：總和 30
  assert.equal(isValidUbn('10458574'), true); // 取 1：總和 29+1
  assert.equal(isValidUbn('10458573'), false); // 28 或 29 都不行
});

test('統編：不合法', () => {
  assert.equal(isValidUbn('12345678'), false);
  assert.equal(isValidUbn('1234567'), false);
  assert.equal(isValidUbn('abcdefgh'), false);
});

test('統編：要有「統編」等關鍵字才偵測，避免日期、訂單號碼誤判', () => {
  assert.deepEqual(types('統編：22099131'), ['ubn']);
  assert.deepEqual(types('統一編號 10000004'), ['ubn']);
  assert.deepEqual(types('Tax ID: 22099131'), ['ubn']);
  assert.deepEqual(types('訂單 22099131'), []);
  assert.deepEqual(types('統編：12345678'), []);
});

// ---------- 信用卡 ----------

test('Luhn', () => {
  assert.equal(isValidLuhn('4111111111111111'), true);
  assert.equal(isValidLuhn('4111111111111112'), false);
  assert.equal(isValidLuhn('12a4'), false);
});

test('信用卡：各發卡組織測試卡號，含空白或連字號分隔', () => {
  assert.deepEqual(types('4111111111111111'), ['credit-card']);
  assert.deepEqual(types('5555 5555 5555 4444'), ['credit-card']);
  assert.deepEqual(types('3782-822463-10005'), ['credit-card']);
  assert.deepEqual(types('卡號 3530111333300000 到期 12/28'), ['credit-card']);
});

test('信用卡：Luhn 不過或開頭不像卡號不算', () => {
  assert.deepEqual(types('4111111111111112'), []);
  // 過 Luhn 但開頭 1 不是任何發卡組織。
  assert.deepEqual(types('1111111111111117'), []);
});

// ---------- 手機 ----------

test('手機：各種寫法', () => {
  assert.deepEqual(types('0912345678'), ['tw-mobile']);
  assert.deepEqual(types('0912-345-678'), ['tw-mobile']);
  assert.deepEqual(types('+886 912 345 678'), ['tw-mobile']);
  assert.deepEqual(types('+886912345678'), ['tw-mobile']);
});

test('手機：市話或更長的數字不算', () => {
  assert.deepEqual(types('0223456789'), []);
  assert.deepEqual(types('09123456789'), []);
  assert.deepEqual(types('109123456789'), []);
});

// ---------- API key ----------

const GHP = `ghp_${'a1B2'.repeat(9)}`; // 36 字
const PAT = `github_pat_11ABCDEFG0123456789_${'x'.repeat(59)}`;
const SKANT = `sk-ant-api03-${'Ab1_-'.repeat(8)}`;
const SK = `sk-proj-${'Zz9'.repeat(10)}`;
const AKIA = 'AKIAIOSFODNN7EXAMPLE';
const XOXB = 'xoxb-1234567890-abcdefghij';
const AIZA = `AIza${'S'.repeat(35)}`;

// 標籤來自共用規則檔 rules/api-keys.json（#26 起與桌面版相同）。Stripe、GitLab、npm 以前只有桌面版有。
const STRIPE = `sk_live_${'Q7'.repeat(12)}`;
const GLPAT = `glpat-${'k9X'.repeat(7)}`;
const NPM = `npm_${'n4P'.repeat(12)}`;

test('API key：各前綴都抓得到，並標示正確種類', () => {
  for (const [key, label] of [
    [GHP, 'GitHub token'], [PAT, 'GitHub token'], [SKANT, 'Anthropic API key'], [SK, 'API key（sk-）'],
    [AKIA, 'AWS access key'], [XOXB, 'Slack token'], [AIZA, 'Google API key'],
    [STRIPE, 'Stripe key'], [GLPAT, 'GitLab token'], [NPM, 'npm token'],
  ]) {
    const found = findSecrets(`export KEY=${key}\n`);
    assert.equal(found.length, 1, key);
    assert.equal(found[0].label, label, key);
    assert.equal(found[0].value, key);
  }
});

test('API key：太短或只是單字不算', () => {
  assert.deepEqual(types('ghp_short'), []);
  assert.deepEqual(types('sk-learn is a library'), []);
  assert.deepEqual(types('AKIA1234'), []);
  assert.deepEqual(types('desk-1234567890abcdefghijkl'), []);
});

// ---------- 多筆、重疊、邊界 ----------

test('多筆機密依位置排序', () => {
  const f = findSecrets(`姓名 王小明 A123456789 電話 0912345678 卡 4111111111111111 key ${GHP}`);
  assert.deepEqual(f.map((x) => x.type), ['tw-id', 'tw-mobile', 'credit-card', 'api-key']);
  for (const x of f) assert.ok(x.start < x.end);
});

test('沒有機密的一般文字回傳空陣列', () => {
  assert.deepEqual(findSecrets('今天天氣很好，會議改到 2024-12-25 下午三點。'), []);
  assert.deepEqual(findSecrets(''), []);
  assert.deepEqual(findSecrets(undefined), []);
});

test('超長文字：結尾的機密也找得到，而且不會卡住', () => {
  const filler = '這是一行很普通的紀錄，沒有機密。log line 0001\n'.repeat(150_000); // 約 4.5M 字
  const text = `${filler}最後：A123456789`;
  const t0 = performance.now();
  const f = findSecrets(text);
  const ms = performance.now() - t0;
  assert.deepEqual(f.map((x) => x.type), ['tw-id']);
  assert.equal(f[0].start, filler.length + 3);
  assert.ok(ms < 5000, `took ${ms} ms`);
});

test('超長文字：超過上限時分析頭尾，中間刻意不分析', () => {
  const half = MAX_SCAN_LENGTH / 2;
  const text = `A123456789 ${' '.repeat(half)}0912000111 ${' '.repeat(half)} 0955666777`;
  assert.deepEqual(findSecrets(text).map((x) => x.value), ['A123456789', '0955666777']);
});

test('病態的超大內容不會卡住', () => {
  for (const text of [
    '1 '.repeat(2_000_000), '4111 '.repeat(800_000), 'A1 '.repeat(1_300_000),
    'A123456789 '.repeat(360_000), '１'.repeat(4_000_000), `eyJ${'a'.repeat(60)}.`.repeat(60_000),
  ]) {
    const t0 = performance.now();
    findSecrets(text);
    const ms = performance.now() - t0;
    assert.ok(ms < 5000, `took ${ms} ms`);
  }
});

// ---------- 正規化（#22） ----------

const fullWidth = (s) => [...s].map((c) => (c >= '!' && c <= '~' ? String.fromCharCode(c.charCodeAt(0) + 0xfee0) : c === ' ' ? '　' : c)).join('');

test('正規化：全形、分隔符號、換行、零寬字元的身分證', () => {
  for (const id of [fullWidth('A123456789'), 'A 123 456 789', 'A12345-6789', 'A12345\n6789', 'A12345\r\n6789',
    'A1234.56789', 'A123​456789', 'A123–456–789']) {
    const text = `身分證：${id}，謝謝`;
    const f = findSecrets(text);
    assert.deepEqual(f.map((x) => x.type), ['tw-id'], JSON.stringify(id));
    assert.equal(text.slice(f[0].start, f[0].end), id);
  }
  for (const bad of ['A 1 2 3 4 5 6 7 8 9', 'A12345  6789', 'A12345-6788', 'XA 123 456 789']) {
    assert.deepEqual(types(bad), [], bad);
  }
});

test('正規化：信用卡點號分隔、全形、折行', () => {
  for (const card of ['4111.1111.1111.1111', fullWidth('4111-1111-1111-1111'), '4111 1111\n1111 1111',
    '3782.822463.10005', '5555​5555​5555​4444']) {
    assert.deepEqual(types(`卡號 ${card} 謝謝`), ['credit-card'], JSON.stringify(card));
  }
  assert.deepEqual(types('4111 1111 1111 1111 12/30'), ['credit-card']);
  for (const bad of ['4111111111\n111111', '4111 1111-1111 1111', '41111.11111.11111.1']) {
    assert.deepEqual(types(bad), [], bad);
  }
});

test('正規化：手機 886、(09)、全形', () => {
  for (const phone of ['886912000111', '+886 0912 000 111', '886-912-000-111', '0912.000.111', '0912\n000111',
    '(09)55666777', '(09) 5566-6777', fullWidth('0955-666-777')]) {
    const text = `電話 ${phone} 找我`;
    const f = findSecrets(text);
    assert.deepEqual(f.map((x) => x.type), ['tw-mobile'], JSON.stringify(phone));
    assert.equal(text.slice(f[0].start, f[0].end), phone);
  }
  for (const bad of ['(02)25556666', '1886912000111', '第 09 屆 12000111 號', '88691200011']) {
    assert.deepEqual(types(bad), [], bad);
  }
});

test('分隔符號不能把不相干的數字湊成機密', () => {
  for (const text of [
    '2024-01-15 2024-02-16 2024-03-17 2024-04-18',
    '4111-11-11 1111-11-11', // 合起來剛好是測試卡號，但分組是日期
    '4111.11.11\n1111.11.11',
    '會議日期：2023/11/22、2023/11/23、2023.11.24',
    '訂單 20240115-0001 20240115-0002 20240115-0003',
    '訂單編號 4000 1234 5678 99',
    '123e4567-e89b-12d3-a456-426614174000',
    '12345678-1234-1234-1234-123456789012',
    '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
    'SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB0ZXN0Lg==',
    '版本 1.2.3.4，下一版 4.1.11.1111',
    '192.168.100.200 10.0.0.1 10.0.0.2 172.16.254.1',
    '今年 09 月 12 日到 345 號 678 室',
    '共 0912 人、345 隊、678 場',
    '明天（星期三）下午三點，在３樓開會：議程共１２項。',
  ]) {
    assert.deepEqual(findSecrets(text), [], text);
  }
});

test('maskText：全形與零寬字元的原文整段換掉', () => {
  const text = `ID ${fullWidth('A123456789')} card 4111​1111​1111​1111 tel 886912000111.`;
  assert.equal(maskText(text), 'ID A12****789 card ************1111 tel 8869*****111.');
});

// ---------- JWT（#22 F15） ----------

const b64url = (s) => Buffer.from(s).toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
const fakeJwt = (header = '{"alg":"HS256","typ":"JWT"}', sig = 'fake-signature-not-real_0123456789') =>
  `${b64url(header)}.${b64url('{"sub":"test-user","name":"Fake"}')}.${sig}`;

test('JWT：命中並遮罩', () => {
  const jwt = fakeJwt();
  const f = findSecrets(`Authorization: Bearer ${jwt}\n`);
  assert.equal(f.length, 1);
  assert.equal(f[0].label, 'JWT');
  assert.equal(f[0].value, jwt);
  assert.equal(maskSecret(f[0]), 'eyJ********6789');
  assert.deepEqual(types(`token 是 ${fakeJwt()}.`), ['api-key']);
  assert.deepEqual(types(fakeJwt('{"alg":"none"}', '')), ['api-key']);
});

test('JWT：header 不對、不像、五段的 JWE 都不算', () => {
  for (const h of ['{"typ":"JWT"}', '{"alg":256}', '{"alg":"HS256" ']) assert.deepEqual(types(fakeJwt(h)), [], h);
  assert.deepEqual(types('eyJhbGciOi.not base64!.x'), []);
  assert.deepEqual(types('eyJzzzzzzzzzzzz.abc.def'), []);
  assert.deepEqual(types(`${fakeJwt()}.${b64url('x')}.${b64url('y')}`), []);
});

// ---------- 遮罩 ----------

test('遮罩：身分證保留前 3 後 3', () => {
  assert.equal(maskSecret({ type: 'tw-id', value: 'A123456789' }), 'A12****789');
});

test('遮罩：信用卡只留末 4 碼且保留分隔符號', () => {
  assert.equal(maskSecret({ type: 'credit-card', value: '4111 1111 1111 1111' }), '**** **** **** 1111');
  assert.equal(maskSecret({ type: 'credit-card', value: '4111111111111111' }), '************1111');
});

test('遮罩：手機、統編', () => {
  assert.equal(maskSecret({ type: 'tw-mobile', value: '0912345678' }), '0912***678');
  assert.equal(maskSecret({ type: 'tw-mobile', value: '0912-345-678' }), '0912-***-678');
  assert.equal(maskSecret({ type: 'tw-mobile', value: '+886912345678' }), '+886912***678');
  assert.equal(maskSecret({ type: 'ubn', value: '22099131' }), '22****31');
});

test('遮罩：API key 保留前綴與末 4 碼，中間壓成 8 個星號', () => {
  assert.equal(maskSecret({ type: 'api-key', value: GHP }), `ghp_********${GHP.slice(-4)}`);
  assert.equal(maskSecret({ type: 'api-key', value: AKIA }), 'AKIA********MPLE');
  assert.ok(!maskSecret({ type: 'api-key', value: SKANT }).includes(SKANT.slice(7, 20)));
});

test('maskText 只換掉機密，其他文字不動', () => {
  assert.equal(maskText('ID: A123456789, tel 0912345678.'), 'ID: A12****789, tel 0912***678.');
  assert.equal(maskText('沒有機密'), '沒有機密');
});
