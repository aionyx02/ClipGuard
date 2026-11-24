import { act, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { MaskPreview, segmentMasked } from '../src/components/MaskPreview';
import { OnionTrace } from '../src/components/OnionTrace';
import { SecretList } from '../src/components/SecretList';
import { VerdictCard } from '../src/components/VerdictCard';
import { fixtureReports } from '../src/fixtures/reports';
import { expectNoAxeViolations, renderUi } from './helpers';
import { setMedia } from './setup';

const zh = fixtureReports('zh-TW');
const en = fixtureReports('en');

afterEach(() => {
  vi.useRealTimers();
});

describe('VerdictCard', () => {
  it('shows action, level, score meter and reasons', async () => {
    const { container } = renderUi(<VerdictCard report={zh.clickfix} />);
    expect(screen.getByRole('heading', { level: 2, name: '已隔離' })).toBeInTheDocument();
    expect(screen.getByText('惡意')).toBeInTheDocument();
    const meter = screen.getByRole('meter', { name: '風險分數' });
    expect(meter).toHaveAttribute('aria-valuenow', '92');
    expect(meter).toHaveAttribute('aria-valuetext', '92 / 100');
    expect(container.querySelectorAll('[data-reason]')).toHaveLength(4);
    expect(screen.getByText('example.invalid')).toBeInTheDocument();
    await expectNoAxeViolations(container);
  });

  it('renders warn with hidden-character reasons, in English', async () => {
    const { container } = renderUi(<VerdictCard report={en.warn} />, 'en');
    expect(screen.getByRole('heading', { name: 'Caution' })).toBeInTheDocument();
    expect(screen.getByText('Suspicious')).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Hidden characters' })).toBeInTheDocument();
    expect(container.querySelector('section')).toHaveAttribute('data-action', 'warn');
    await expectNoAxeViolations(container);
  });

  it('clamps the score and shows the truncation note', () => {
    const report = {
      ...zh.clean,
      truncated: true,
      command: { ...zh.clean.command, risk_score: 140 },
    };
    renderUi(<VerdictCard report={report} />);
    expect(screen.getByRole('meter')).toHaveAttribute('aria-valuenow', '100');
    expect(screen.getByText('內容太長，只分析了開頭的部分。')).toBeInTheDocument();
  });
});

describe('OnionTrace', () => {
  const trace = zh.clickfix.command.trace;

  it('reveals layers one by one while auto-playing', () => {
    vi.useFakeTimers();
    const { container } = renderUi(<OnionTrace trace={trace} intervalMs={100} />);
    expect(container.querySelectorAll('[data-layer]')).toHaveLength(1);
    act(() => vi.advanceTimersByTime(100));
    expect(container.querySelectorAll('[data-layer]')).toHaveLength(2);
    for (let i = 0; i < 5; i++) act(() => vi.advanceTimersByTime(100));
    expect(container.querySelectorAll('[data-layer]')).toHaveLength(4);
    expect(screen.getByText('已展開 4 / 4 層')).toBeInTheDocument();
  });

  it('nests each layer inside the previous one', () => {
    const { container } = renderUi(<OnionTrace trace={trace} autoPlay={false} />);
    const inner = container.querySelector('[data-layer="4"]');
    expect(inner?.parentElement?.closest('[data-layer]')).toHaveAttribute('data-layer', '3');
    expect(within(inner as HTMLElement).getByText('最內層：實際內容')).toBeInTheDocument();
  });

  it('shows everything at once under prefers-reduced-motion', () => {
    setMedia('(prefers-reduced-motion: reduce)', true);
    const { container } = renderUi(<OnionTrace trace={trace} />);
    expect(container.querySelectorAll('[data-layer]')).toHaveLength(4);
  });

  it('is keyboard operable and announces revealed layers', async () => {
    const user = userEvent.setup();
    renderUi(<OnionTrace trace={trace} autoPlay={false} />, 'en');
    // autoPlay=false starts fully revealed; replay goes back to the first layer.
    const replay = screen.getByRole('button', { name: 'Replay' });
    replay.focus();
    await user.keyboard('{Enter}');
    expect(document.querySelectorAll('[data-layer]')).toHaveLength(1);

    const next = screen.getByRole('button', { name: 'Reveal next layer' });
    next.focus();
    await user.keyboard('{Enter}');
    expect(document.querySelectorAll('[data-layer]')).toHaveLength(2);
    const live = document.querySelector('[aria-live="polite"]');
    expect(live?.textContent).toContain('Layer 2');
    expect(live?.textContent).toContain(trace[1]?.preview);

    await user.keyboard('{Enter}{Enter}{Enter}');
    expect(document.querySelectorAll('[data-layer]')).toHaveLength(4);
    // Focus stays on the (now aria-disabled) button instead of falling to <body>.
    expect(next).toHaveFocus();
    expect(next).toHaveAttribute('aria-disabled', 'true');
  });

  it('handles an empty trace and passes axe', async () => {
    const { container } = renderUi(<OnionTrace trace={[]} />);
    expect(screen.getByText('這段內容沒有經過混淆。')).toBeInTheDocument();
    expect(screen.queryByRole('button')).toBeNull();
    await expectNoAxeViolations(container);
  });

  it('passes axe when fully revealed', async () => {
    const { container } = renderUi(<OnionTrace trace={trace} autoPlay={false} />);
    await expectNoAxeViolations(container);
  });
});

describe('SecretList and MaskPreview', () => {
  it('lists masked values only', async () => {
    const { container } = renderUi(<SecretList secrets={zh.secrets.secrets} />);
    expect(screen.getAllByRole('listitem')).toHaveLength(3);
    expect(screen.getByText('A1*******9')).toBeInTheDocument();
    expect(screen.getByText('tw-national-id')).toBeInTheDocument();
    await expectNoAxeViolations(container);
  });

  it('shows an empty state', () => {
    renderUi(<SecretList secrets={[]} />, 'en');
    expect(screen.getByText('No secrets found.')).toBeInTheDocument();
  });

  it('highlights masked values inside the masked text', async () => {
    const { container } = renderUi(
      <MaskPreview masked={zh.secretsMaskedText} secrets={zh.secrets.secrets} />,
    );
    const marks = [...container.querySelectorAll('mark')].map((m) => m.textContent);
    expect(marks).toEqual(['A1*******9', '4111 **** **** 1111', 'sk-p…****…Q3x']);
    await expectNoAxeViolations(container);
  });

  it('segments overlapping needles longest-first', () => {
    expect(segmentMasked('ab**cd', ['**', 'b**'])).toEqual([
      { text: 'a', mark: false, start: 0 },
      { text: 'b**', mark: true, start: 1 },
      { text: 'cd', mark: false, start: 4 },
    ]);
    expect(segmentMasked('plain', [])).toEqual([{ text: 'plain', mark: false, start: 0 }]);
  });
});
