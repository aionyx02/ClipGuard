// Native Messaging link to the PasteWarden desktop app (docs/plan/phase-4.md §4.3–§4.5,
// docs/spikes/s9-native-messaging.md).
//
// Optional by design: the extension works fully without the desktop app. `nativeMessaging` is an
// optional permission the user grants from the options page; until then nothing here runs. With
// the permission, the background probes once with `hello` (sendNativeMessage), and on failure
// stays quiet and retries later with backoff (EXT_PROBE_RETRY_MS → EXT_PROBE_RETRY_MAX_MS).
//
// Messages never carry clipboard or input text, unmasked secrets, URLs (host only) or keys: the
// only thing sent besides `hello` is a `verdict` (rule id, severity, host, action).
//
// No timers: a service worker can be killed at any time, so the probe schedule lives in
// storage.local and is checked lazily (background start, before a verdict, options page).

export const NMH_NAME = 'org.pastewarden.nmh';
export const NMH_PROTOCOL_VERSION = 1;
/** First retry after a failed probe (10 min); doubles per failure up to the max. */
export const EXT_PROBE_RETRY_MS = 600_000;
/** Longest retry interval (60 min); also how often a working link is re-checked. */
export const EXT_PROBE_RETRY_MAX_MS = 3_600_000;
export const NATIVE_KEY = 'native';
/** What the extension tells the host it can do. */
export const EXT_CAPS = ['verdict'] as const;

/**
 * - `off`: the user hasn't granted `nativeMessaging` (default)
 * - `absent`: no host installed (or not allowed / crashed)
 * - `not_running`: host installed, desktop app not running
 * - `incompatible`: protocol version mismatch: the extension works alone
 * - `running`: connected
 */
export type DesktopState = 'off' | 'absent' | 'not_running' | 'incompatible' | 'running';

export interface NativeRecord {
  state: DesktopState;
  /** Consecutive failed probes. */
  failures: number;
  /** ms since epoch; 0 = probe now. */
  nextProbeAt: number;
}

export const INITIAL_RECORD: NativeRecord = { state: 'off', failures: 0, nextProbeAt: 0 };

const STATES: readonly DesktopState[] = ['off', 'absent', 'not_running', 'incompatible', 'running'];

export function normalizeRecord(raw: unknown): NativeRecord {
  const r = (raw && typeof raw === 'object' ? raw : {}) as Record<string, unknown>;
  const num = (v: unknown) => (typeof v === 'number' && Number.isFinite(v) && v >= 0 ? v : 0);
  return {
    state: STATES.includes(r.state as DesktopState) ? (r.state as DesktopState) : 'off',
    failures: Math.floor(num(r.failures)),
    nextProbeAt: num(r.nextProbeAt),
  };
}

/** Delay before the next probe after `failures` consecutive failures (≥ 1). */
export function retryDelay(failures: number): number {
  const n = Number.isFinite(failures) ? Math.max(1, Math.floor(failures)) : 1;
  // 2 ** 3 already exceeds the cap; avoid huge exponents.
  return Math.min(EXT_PROBE_RETRY_MS * 2 ** Math.min(n - 1, 8), EXT_PROBE_RETRY_MAX_MS);
}

/** The desktop state a `hello` reply means. Anything unexpected counts as `absent`. */
export function classifyHello(reply: unknown): Exclude<DesktopState, 'off'> {
  if (!reply || typeof reply !== 'object') return 'absent';
  const r = reply as Record<string, unknown>;
  if (r.ok === false && r.err === 'version') return 'incompatible';
  if (r.ok !== true || r.v !== NMH_PROTOCOL_VERSION) return 'absent';
  if (r.desktop === 'running') return 'running';
  if (r.desktop === 'not_running') return 'not_running';
  return 'absent';
}

/** Record after a probe (or a failed send) that found `state`. */
export function nextRecord(prev: NativeRecord, state: DesktopState, now: number): NativeRecord {
  if (state === 'off') return { ...INITIAL_RECORD };
  if (state === 'running') return { state, failures: 0, nextProbeAt: now + EXT_PROBE_RETRY_MAX_MS };
  const failures = prev.failures + 1;
  return { state, failures, nextProbeAt: now + retryDelay(failures) };
}

export type Severity = 'low' | 'medium' | 'high';
export type VerdictAction = 'blocked' | 'warned' | 'confirm';

/** What the extension already showed in the page; the desktop only logs it. */
export interface VerdictInfo {
  /** Rule id: a secret's `rule_id`, a reason id, or the record kind. */
  kind: string;
  severity: Severity;
  action: VerdictAction;
}

const RULE_ID = /^[A-Za-z0-9._-]{1,96}$/;

/** `id` if it is a valid rule id, else `fallback`. */
export function ruleIdOr(id: string | undefined, fallback: string): string {
  return id !== undefined && RULE_ID.test(id) ? id : fallback;
}
const HOST = /^[a-z0-9.\-:[\]]{0,253}$/;

/** The `verdict` message, or null when a field wouldn't pass the host's validation. */
export function verdictMessage(
  v: VerdictInfo,
  host: string,
  id: number,
): Record<string, unknown> | null {
  const h = host.toLowerCase().replace(/\.$/, '');
  if (!RULE_ID.test(v.kind) || !HOST.test(h)) return null;
  if (!['low', 'medium', 'high'].includes(v.severity)) return null;
  if (!['blocked', 'warned', 'confirm'].includes(v.action)) return null;
  return {
    v: NMH_PROTOCOL_VERSION,
    id,
    op: 'verdict',
    kind: v.kind,
    severity: v.severity,
    origin_host: h,
    action: v.action,
  };
}

export interface NativeDeps {
  /** Whether `nativeMessaging` is granted. */
  hasPermission(): Promise<boolean>;
  /** `runtime.sendNativeMessage(NMH_NAME, msg)`; rejects when there is no host. */
  send(msg: Record<string, unknown>): Promise<unknown>;
  load(): Promise<unknown>;
  save(r: NativeRecord): Promise<void>;
  now(): number;
  /** Extension version for `hello`. */
  version: string;
}

export class NativeLink {
  private inflight: Promise<NativeRecord> | null = null;
  private nextId = 1;

  constructor(private readonly deps: NativeDeps) {}

  async status(): Promise<NativeRecord> {
    try {
      return normalizeRecord(await this.deps.load());
    } catch {
      return { ...INITIAL_RECORD };
    }
  }

  /** Probes if one is due (or `force`). Never throws. */
  probe(force = false): Promise<NativeRecord> {
    if (!this.inflight) {
      this.inflight = this.doProbe(force).finally(() => {
        this.inflight = null;
      });
    }
    return this.inflight;
  }

  private async doProbe(force: boolean): Promise<NativeRecord> {
    const prev = await this.status();
    if (!(await this.permitted())) return this.store(prev, 'off');
    const now = this.deps.now();
    if (!force && prev.state !== 'off' && now < prev.nextProbeAt) return prev;
    let state: DesktopState;
    try {
      const reply = await this.deps.send({
        v: NMH_PROTOCOL_VERSION,
        id: this.id(),
        op: 'hello',
        ext: { ver: this.deps.version, caps: [...EXT_CAPS] },
      });
      state = classifyHello(reply);
    } catch {
      // No host / not allowed / host crashed: quiet downgrade (S9).
      state = 'absent';
    }
    // A forced probe that still fails restarts the backoff from the first step.
    return this.store(force && state !== 'running' ? INITIAL_RECORD : prev, state);
  }

  /** Sends a verdict when the desktop app is connected. Never throws; false if not sent. */
  async sendVerdict(v: VerdictInfo, host: string): Promise<boolean> {
    const rec = await this.probe();
    if (rec.state !== 'running') return false;
    const msg = verdictMessage(v, host, this.id());
    if (!msg) return false;
    try {
      const reply = (await this.deps.send(msg)) as Record<string, unknown> | null;
      if (reply?.ok === true) return true;
      if (reply?.desktop === 'not_running') await this.store(rec, 'not_running');
      return false;
    } catch {
      await this.store(rec, 'absent');
      return false;
    }
  }

  private async permitted(): Promise<boolean> {
    try {
      return await this.deps.hasPermission();
    } catch {
      return false;
    }
  }

  private async store(prev: NativeRecord, state: DesktopState): Promise<NativeRecord> {
    const next = nextRecord(prev, state, this.deps.now());
    try {
      await this.deps.save(next);
    } catch {
      // Storage failures only mean we probe again sooner.
    }
    return next;
  }

  private id(): number {
    const id = this.nextId;
    this.nextId = id >= Number.MAX_SAFE_INTEGER ? 1 : id + 1;
    return id;
  }
}
