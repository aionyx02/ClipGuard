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

test('API key：各前綴都抓得到，並標示正確種類', () => {
  for (const [key, label] of [
    [GHP, 'GitHub Token'], [PAT, 'GitHub Token'], [SKANT, 'Anthropic API Key'], [SK, 'OpenAI API Key'],
    [AKIA, 'AWS Access Key'], [XOXB, 'Slack Token'], [AIZA, 'Google API Key'],
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

test('超長文字只掃前段，不會卡住', () => {
  const text = `${'x '.repeat(MAX_SCAN_LENGTH)}A123456789`;
  assert.deepEqual(findSecrets(text), []);
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
