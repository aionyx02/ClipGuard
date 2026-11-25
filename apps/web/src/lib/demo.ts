/**
 * Timelines of the home-page demo: simulated attacks, played as animations instead of video
 * files. The CSP has no `media-src`, and an animation follows the theme and language.
 * Each scenario is data (chapters, captions, named spans); `frameAt` is pure, so it is tested
 * without a browser. Only behaviour PasteWarden really has is shown (docs: user/features.md).
 */

export type ScenarioId = 'clickfix' | 'secrets' | 'pastejack' | 'hidden';

interface Mark {
  id: string;
  start: number;
}

export interface Scenario {
  id: ScenarioId;
  /** Loop length in milliseconds. */
  length: number;
  chapters: readonly Mark[];
  captions: readonly Mark[];
  /** Named intervals [start, end) in ms; `end` defaults to the end of the scenario. */
  spans: Readonly<Record<string, readonly [number, number?]>>;
}

export const SCENARIOS: readonly Scenario[] = [
  {
    // A fake CAPTCHA writes a command to the clipboard: blocked at write time, the clipboard
    // holds a harmless notice, so following the steps pastes only that notice.
    id: 'clickfix',
    length: 13_000,
    chapters: [
      { id: 'bait', start: 0 },
      { id: 'catch', start: 3_000 },
      { id: 'safe', start: 6_400 },
    ],
    captions: [
      { id: 'bait', start: 0 },
      { id: 'copy', start: 1_550 },
      { id: 'catch', start: 3_000 },
      { id: 'safe', start: 6_400 },
    ],
    spans: {
      'cursor-checkbox': [300, 6_400],
      'cursor-run': [6_400, 8_800],
      checked: [1_400],
      xray: [1_550, 3_000],
      steps: [2_200],
      warning: [3_000],
      run: [6_400],
      'key-win-r': [6_400, 7_200],
      'key-ctrl-v': [7_600, 8_300],
      pasted: [8_000],
    },
  },
  {
    // Pasting a token into an AI chat: PasteWarden asks first, Enter pastes the masked version.
    id: 'secrets',
    length: 13_000,
    chapters: [
      { id: 'copy', start: 0 },
      { id: 'ask', start: 2_900 },
      { id: 'masked', start: 6_600 },
    ],
    captions: [
      { id: 'copy', start: 0 },
      { id: 'paste', start: 2_000 },
      { id: 'ask', start: 2_900 },
      { id: 'masked', start: 6_600 },
    ],
    spans: {
      'cursor-input': [600, 2_900],
      clipboard: [0, 2_900],
      'key-ctrl-v': [2_100, 2_900],
      dialog: [2_900, 6_600],
      'key-enter': [5_800, 6_600],
      masked: [6_600],
      sent: [8_400],
    },
  },
  {
    // The page swaps what you copied for a download-and-run line: blocked at write time.
    id: 'pastejack',
    length: 12_000,
    chapters: [
      { id: 'select', start: 0 },
      { id: 'swap', start: 1_900 },
      { id: 'catch', start: 2_700 },
    ],
    captions: [
      { id: 'select', start: 0 },
      { id: 'swap', start: 1_900 },
      { id: 'catch', start: 2_700 },
      { id: 'safe', start: 6_500 },
    ],
    spans: {
      'cursor-sel-a': [200, 700],
      'cursor-sel-b': [700, 1_900],
      selected: [700],
      'key-ctrl-c': [1_200, 1_900],
      xray: [1_900],
      warning: [2_700],
    },
  },
  {
    // A shared prompt hides instructions for an AI in invisible Unicode TAG characters: warned.
    id: 'hidden',
    length: 12_000,
    chapters: [
      { id: 'copy', start: 0 },
      { id: 'warn', start: 1_700 },
      { id: 'reveal', start: 3_800 },
    ],
    captions: [
      { id: 'copy', start: 0 },
      { id: 'warn', start: 1_700 },
      { id: 'reveal', start: 3_800 },
    ],
    spans: {
      'cursor-copy': [300, 1_700],
      copied: [1_400],
      warning: [1_700],
      xray: [3_800],
    },
  },
];

export function scenario(id: ScenarioId): Scenario {
  return SCENARIOS.find((s) => s.id === id) ?? (SCENARIOS[0] as Scenario);
}

export function nextScenario(id: ScenarioId): ScenarioId {
  const i = SCENARIOS.findIndex((s) => s.id === id);
  return (SCENARIOS[(i + 1) % SCENARIOS.length] as Scenario).id;
}

function markAt(marks: readonly Mark[], t: number): string {
  let current = marks[0]?.id ?? '';
  for (const m of marks) if (t >= m.start) current = m.id;
  return current;
}

export interface Frame {
  scenario: ScenarioId;
  /** Time inside the scenario, 0 ≤ t < length. */
  t: number;
  chapter: string;
  caption: string;
  /** Whether a named span is active. Unknown names are never active. */
  on: (span: string) => boolean;
}

export function frameAt(s: Scenario, time: number): Frame {
  const raw = Number.isFinite(time) ? time : 0;
  const t = ((raw % s.length) + s.length) % s.length;
  return {
    scenario: s.id,
    t,
    chapter: markAt(s.chapters, t),
    caption: markAt(s.captions, t),
    on: (name) => {
      const span = s.spans[name];
      if (!span) return false;
      const [start, end = s.length] = span;
      return t >= start && t < end;
    },
  };
}

/** The still frame shown when motion is reduced: the end of the story. */
export const stillTime = (s: Scenario) => s.length - 1;
