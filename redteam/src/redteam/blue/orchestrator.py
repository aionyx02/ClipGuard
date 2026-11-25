"""Blue-team orchestrator (docs/plan/phase-5.md §5.5).

The blue agent (``opencode run`` on a free model) may only change ``rules/``
and ``corpus/`` and may only end in a draft PR. Both limits are enforced here
and in the opencode plugin, not by the prompt:

1. a sparse worktree without ``redteam/`` (heldout and run stores are absent),
2. ``pw-blue-guard.ts`` + ``pw-blue-policy.mjs`` (default-deny tool policy),
3. post-checks on the resulting diff and a full corpus run (``check_round``),
4. the orchestrator, not the agent, commits and opens the PR. There is no
   merge code path anywhere in this package (tests/test_static_guards.py).
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from redteam.engine import CACHE_DIR, REPO_ROOT
from redteam.models import EngineVerdict, Seed, SyntaxVerdict, Variant
from redteam.store import RunStore, encode, to_parts

BLUE_DIR = Path(__file__).resolve().parent
PLUGIN_FILES = ('pw-blue-guard.ts', 'pw-blue-policy.mjs')

MAX_BYPASSES_PER_ROUND = 40
BLUE_MAX_TOOL_CALLS = 150
BLUE_MAX_ATTEMPTS = 2
BLUE_TIMEOUT_MIN = 45
# Blue rounds branch from and PR into the Phase 5 branch (phase-5.md §5.2).
BLUE_BASE = 'feature/phase-5-agent'
BLUE_MODELS = (
    'opencode/deepseek-v4.1-flash-free',
    'opencode/mimo-v2.6-flash-free',
    'opencode/nemotron-3.5-super-vl-free',
)

ALLOWED_PREFIXES = (
    'rules/',
    'corpus/cases/',
    'corpus/benign/',
    'corpus/divergences/',
)
HANDOFF = '.pw-blue'
GIT_EXCLUDES = ('/.pw-blue/', '/.opencode/')

# Commands run inside the worktree after the agent stops (§5.5.2 item 4).
CHECK_COMMANDS: tuple[tuple[str, ...], ...] = (
    ('cargo', 'run', '-q', '-p', 'xtask', '--', 'corpus', 'lint'),
    ('cargo', 'run', '-q', '-p', 'xtask', '--', 'corpus', 'run'),
    ('cargo', 'run', '-q', '-p', 'xtask', '--', 'corpus', 'benign'),
    ('cargo', 'test', '-q', '-p', 'paste-warden-rules', '-p',
     'paste-warden-core'),
)  # fmt: skip


class BlueError(RuntimeError):
    """Setup or git failure (never carries payload text)."""


# -- selection ---------------------------------------------------------------


def select_bypasses(
    variants: Iterable[Variant],
    verdicts: Iterable[EngineVerdict],
    syntax: dict[str, SyntaxVerdict],
    seeds: Iterable[Seed],
    limit: int = MAX_BYPASSES_PER_ROUND,
) -> list[tuple[Variant, EngineVerdict]]:
    """Train-split, syntax-valid variants the engine did not block.

    Clustered by (technique chain, reason ids); clusters are visited
    round-robin, full bypasses before downgrades, so ``limit`` samples cover
    as many distinct weaknesses as possible.
    """
    train = {s.case_id for s in seeds if s.split == 'train'}
    by_id = {v.id: v for v in variants}
    clusters: dict[tuple, list[tuple[Variant, EngineVerdict]]] = {}
    for verdict in sorted(verdicts, key=lambda x: x.variant_id):
        v = by_id.get(verdict.variant_id)
        if v is None or v.seed_id not in train:
            continue
        if verdict.outcome == 'blocked':
            continue
        sv = syntax.get(v.id)
        if sv is None or not sv.ok:
            continue
        key = (
            verdict.outcome != 'bypassed',
            v.techniques,
            verdict.reason_ids,
        )
        clusters.setdefault(key, []).append((v, verdict))
    picked: list[tuple[Variant, EngineVerdict]] = []
    queues = [clusters[k] for k in sorted(clusters)]
    while queues and len(picked) < limit:
        for q in list(queues):
            if len(picked) >= limit:
                break
            picked.append(q.pop(0))
            if not q:
                queues.remove(q)
    return picked


# -- worktree ----------------------------------------------------------------


def _git(args: Sequence[str], cwd: Path, check: bool = True) -> str:
    r = subprocess.run(
        ['git', *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=300,
    )
    if check and r.returncode != 0:
        raise BlueError(f'git {args[0]} failed ({r.returncode})')
    return r.stdout


def branch_name(round_: int) -> str:
    return f'redteam/round-{round_}'


def create_worktree(
    round_: int, base: str, repo: Path = REPO_ROOT, root: Path | None = None
) -> Path:
    """Sparse worktree on ``redteam/round-<N>`` without ``redteam/``."""
    root = root or CACHE_DIR / 'blue'
    root.mkdir(parents=True, exist_ok=True)
    wt = root / f'round-{round_}'
    if wt.exists():
        raise BlueError(f'worktree already exists: {wt.name}')
    _git(
        ['worktree', 'add', '--no-checkout', '-b', branch_name(round_),
         str(wt), base],
        repo,
    )  # fmt: skip
    _git(['sparse-checkout', 'set', '--no-cone', '/*', '!/redteam/'], wt)
    _git(['checkout'], wt)
    if (wt / 'redteam').exists():
        raise BlueError('sparse checkout left redteam/ in the worktree')
    git_path = _git(['rev-parse', '--git-path', 'info/exclude'], wt)
    exclude = Path(git_path.strip())
    if not exclude.is_absolute():
        exclude = wt / exclude
    exclude.parent.mkdir(parents=True, exist_ok=True)
    existing = exclude.read_text() if exclude.exists() else ''
    missing = [e for e in GIT_EXCLUDES if e not in existing.splitlines()]
    if missing:
        with exclude.open('a') as f:
            f.write(''.join(f'{e}\n' for e in missing))
    return wt


def remove_worktree(wt: Path, repo: Path = REPO_ROOT) -> None:
    _git(['worktree', 'remove', '--force', str(wt)], repo, check=False)


def write_handoff(
    wt: Path, picked: Sequence[tuple[Variant, EngineVerdict]], run_id: str
) -> Path:
    """``.pw-blue/blue-input.jsonl`` and the bypass-only ``.pw-blue/store``.

    Payloads appear only as ``parts`` (§5.3.4). ``source`` lets the agent run
    ``corpus add-from-run .pw-blue/store <id>``.
    """
    hand = wt / HANDOFF
    store = hand / 'store'
    store.mkdir(parents=True, exist_ok=True)
    with (hand / 'blue-input.jsonl').open('w', encoding='utf-8') as f:
        for v, verdict in picked:
            record = {
                'variant_id': v.id,
                'seed_id': v.seed_id,
                'shell': v.shell.value,
                'generator': v.generator,
                'techniques': list(v.techniques),
                'action': verdict.action,
                'risk_score': verdict.risk_score,
                'reason_ids': list(verdict.reason_ids),
                'parts': to_parts(v.payload),
            }
            f.write(json.dumps(record, ensure_ascii=False) + '\n')
    with (store / 'variants.jsonl').open('w', encoding='utf-8') as f:
        for v, _ in picked:
            f.write(json.dumps(encode(v), ensure_ascii=False) + '\n')
    (hand / 'run-id').write_text(run_id + '\n')
    return hand


def install_plugin(wt: Path) -> None:
    """Plugin + project config into ``.opencode/`` (git-excluded)."""
    plugins = wt / '.opencode' / 'plugins'
    plugins.mkdir(parents=True, exist_ok=True)
    for name in PLUGIN_FILES:
        shutil.copyfile(BLUE_DIR / name, plugins / name)
    config = {
        '$schema': 'https://opencode.ai/config.json',
        # Depth in defense only: pw-blue-guard is the enforcing layer.
        'permission': {
            'webfetch': 'deny',
            'websearch': 'deny',
            'bash': {
                '*': 'deny',
                'cargo run -p xtask -- corpus *': 'allow',
                'cargo test -p paste-warden-rules*': 'allow',
                'cargo test -p paste-warden-core*': 'allow',
            },
            'edit': {
                '*': 'deny',
                'rules/**': 'allow',
                'corpus/**': 'allow',
                f'{HANDOFF}/blue-output.json': 'allow',
            },
        },
        'mcp': {},
    }
    (wt / '.opencode' / 'opencode.json').write_text(
        json.dumps(config, indent=2) + '\n'
    )


# -- the agent run -----------------------------------------------------------


def task_prompt(round_: int, n: int, feedback: str | None = None) -> str:
    """The blue task. It names files, never payloads."""
    text = f"""You are the blue team of PasteWarden, a clipboard-security tool.
A red team found {n} command variants that the detection engine does not
block. Make the engine block them by changing DATA ONLY.

Inputs (read-only): {HANDOFF}/blue-input.jsonl, one JSON object per line with
variant_id, shell, techniques, the engine's action/risk_score/reason_ids, and
`parts` (join the strings in order to get the command; it was never run and
must never be run).

Steps:
1. For each variant decide whether it means the same as a malicious command
   (same download and execution behaviour). Write {HANDOFF}/blue-output.json
   as {{"judgments": [{{"variant_id": "...", "verdict": "equivalent" |
   "not_equivalent" | "unsure", "reason": "short"}}]}}. Only fix equivalent
   ones.
2. Change rule data under rules/ (read docs/spec/detection-rules.md §3 and
   §5.4 first: Rust `regex` syntax only, no lookaround or backreferences).
   You cannot change engine code; some variants may be unfixable with data
   alone, so skip those and say why.
3. For every fixed variant add the corpus case with exactly:
   cargo run -p xtask -- corpus add-from-run {HANDOFF}/store <variant_id> \\
     --expect malicious --file redteam-r{round_}
   Never type a command payload into any file yourself.
4. For every rule you add or change, also add at least one benign case that
   must NOT match (a JSON line in corpus/cases/redteam-r{round_}-benign.jsonl
   with "expect": {{"level": "none"}}; copy the format of existing cases).
   Never modify or delete existing corpus lines.
5. Run `cargo run -p xtask -- corpus run` and
   `cargo run -p xtask -- corpus benign` until both report 0 failures and 0
   flagged benign samples.

Allowed shell commands: `cargo run -p xtask -- corpus ...`,
`cargo test -p paste-warden-rules`, `cargo test -p paste-warden-core`.
Everything else (git, network, other paths) is blocked by policy. When done,
reply with a short summary of what you changed and what you skipped."""
    if feedback:
        text += (
            '\n\nYour previous attempt failed the orchestrator checks:\n'
            f'{feedback}\nFix these problems; keep the good changes.'
        )
    return text


@dataclass
class AgentRun:
    model: str
    returncode: int | None
    timed_out: bool
    minutes: float
    tool_calls: int
    log: Path


def run_agent(
    wt: Path,
    prompt: str,
    model: str,
    *,
    pw_bin: Path,
    log: Path,
    denials: Path,
    timeout_min: float = BLUE_TIMEOUT_MIN,
    max_tool_calls: int = BLUE_MAX_TOOL_CALLS,
    opencode: str = 'opencode',
) -> AgentRun:
    env = {
        k: v
        for k, v in os.environ.items()
        if k in ('PATH', 'HOME', 'USER', 'LANG', 'TMPDIR', 'CARGO_HOME',
                 'RUSTUP_HOME', 'SHELL', 'TERM')
    }  # fmt: skip
    env.update(
        PW_BLUE_ROOT=str(wt),
        PW_BIN=str(pw_bin),
        PW_BLUE_DENIALS=str(denials),
        PW_BLUE_MAX_TOOL_CALLS=str(max_tool_calls),
    )
    cmd = [opencode, 'run', '--standalone', '--auto', '--format', 'json',
           '-m', model, prompt]  # fmt: skip
    start = time.monotonic()
    timed_out = False
    with log.open('w', encoding='utf-8') as out:
        proc = subprocess.Popen(
            cmd,
            cwd=wt,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=out,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        try:
            proc.wait(timeout=timeout_min * 60)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
    return AgentRun(
        model=model,
        returncode=proc.returncode,
        timed_out=timed_out,
        minutes=(time.monotonic() - start) / 60,
        tool_calls=count_tool_calls(log),
        log=log,
    )


def count_tool_calls(log: Path) -> int:
    n = 0
    if not log.exists():
        return 0
    for line in log.read_text(encoding='utf-8', errors='replace').splitlines():
        try:
            if json.loads(line).get('type') == 'tool_use':
                n += 1
        except (json.JSONDecodeError, AttributeError):
            continue
    return n


# -- post-checks (§5.5.2) ----------------------------------------------------


@dataclass
class CheckResult:
    ok: bool
    problems: list[str] = field(default_factory=list)
    changed: list[str] = field(default_factory=list)
    rules_lines: int = 0
    cases_added: int = 0
    judgments: dict[str, str] = field(default_factory=dict)

    def feedback(self) -> str:
        return '\n'.join(f'- {p}' for p in self.problems)


def stage_all(wt: Path) -> None:
    _git(['add', '-A', '--', '.'], wt)


def changed_files(wt: Path, base: str) -> list[str]:
    out = _git(['diff', '--cached', '--name-only', base], wt)
    return [line for line in out.splitlines() if line]


def path_problems(paths: Iterable[str]) -> list[str]:
    bad = [p for p in paths if not p.startswith(ALLOWED_PREFIXES)]
    return [f'changed a file outside rules/ and corpus/: {p}' for p in bad]


def removed_corpus_lines(wt: Path, base: str) -> list[str]:
    """Corpus files may only gain lines (§5.5.2 item 2)."""
    out = _git(['diff', '--cached', '--unified=0', base, '--', 'corpus/'], wt)
    files: list[str] = []
    current = None
    for line in out.splitlines():
        if line.startswith('--- '):
            current = line[6:] if line.startswith('--- a/') else None
        elif line.startswith('-') and not line.startswith('---'):
            if current and current not in files:
                files.append(current)
    return files


def added_case_levels(wt: Path, base: str) -> list[str]:
    out = _git(
        ['diff', '--cached', '--unified=0', base, '--', 'corpus/cases/'], wt
    )
    levels = []
    for line in out.splitlines():
        if line.startswith('+') and not line.startswith('+++'):
            try:
                case = json.loads(line[1:])
            except json.JSONDecodeError:
                levels.append('unparseable')
                continue
            levels.append(str((case.get('expect') or {}).get('level')))
    return levels


def rules_lines_changed(wt: Path, base: str) -> int:
    out = _git(['diff', '--cached', '--numstat', base, '--', 'rules/'], wt)
    total = 0
    for line in out.splitlines():
        added, removed, *_ = line.split('\t')
        if added.isdigit() and removed.isdigit():
            total += int(added) + int(removed)
    return total


def read_judgments(wt: Path) -> dict[str, str]:
    path = wt / HANDOFF / 'blue-output.json'
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, json.JSONDecodeError):
        return {}
    out = {}
    for j in data.get('judgments', []) if isinstance(data, dict) else []:
        if isinstance(j, dict) and isinstance(j.get('variant_id'), str):
            verdict = j.get('verdict')
            if verdict in ('equivalent', 'not_equivalent', 'unsure'):
                out[j['variant_id']] = verdict
    return out


Runner = Callable[[Sequence[str], Path], int]


def _run_check(cmd: Sequence[str], cwd: Path) -> int:
    r = subprocess.run(
        list(cmd),
        cwd=cwd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=1800,
    )
    return r.returncode


def check_round(
    wt: Path, base: str, *, run_checks: Runner | None = _run_check
) -> CheckResult:
    """Everything §5.5.2 can decide from the worktree alone.

    Items 5 (heldout p99) and 6 (at least one bypass fixed) need a commit and
    an engine build; ``run_round`` does them after this passes.
    """
    stage_all(wt)
    changed = changed_files(wt, base)
    problems = path_problems(changed)
    for f in removed_corpus_lines(wt, base):
        problems.append(f'removed or edited existing corpus lines in {f}')
    levels = added_case_levels(wt, base)
    if 'unparseable' in levels:
        problems.append('added a corpus line that is not valid JSON')
    rules_lines = rules_lines_changed(wt, base)
    if not changed:
        problems.append('no changes to rules/ or corpus/')
    must_match = any(lv in ('malicious', 'suspicious') for lv in levels)
    if rules_lines and not must_match:
        problems.append('changed rules without adding a must-match case')
    if rules_lines and 'none' not in levels:
        problems.append('changed rules without adding a must-not-match case')
    if not problems and run_checks is not None:
        for cmd in CHECK_COMMANDS:
            if run_checks(cmd, wt) != 0:
                problems.append(f'`{" ".join(cmd)}` failed')
    return CheckResult(
        ok=not problems,
        problems=problems,
        changed=changed,
        rules_lines=rules_lines,
        cases_added=len(levels),
        judgments=read_judgments(wt),
    )


def commit_round(wt: Path, round_: int, message: str) -> str:
    branch = _git(['rev-parse', '--abbrev-ref', 'HEAD'], wt).strip()
    if branch != branch_name(round_):
        raise BlueError('worktree is not on its redteam/round branch')
    stage_all(wt)
    _git(
        ['-c', 'user.name=PasteWarden blue team',
         '-c', 'user.email=blue-team@example.invalid',
         'commit', '-q', '-m', message],
        wt,
    )  # fmt: skip
    return _git(['rev-parse', 'HEAD'], wt).strip()


def push_and_open_pr(
    wt: Path, round_: int, title: str, body: str, base: str
) -> str:
    """Push the round branch and open a DRAFT PR to ``base``. Never merges."""
    branch = branch_name(round_)
    if not branch.startswith('redteam/'):
        raise BlueError('refusing to push a non-redteam branch')
    _git(['push', '-u', 'origin', f'{branch}:{branch}'], wt)
    r = subprocess.run(
        ['gh', 'pr', 'create', '--draft', '--base', base, '--head', branch,
         '--title', title, '--body', body],
        cwd=wt,
        capture_output=True,
        text=True,
        timeout=120,
    )  # fmt: skip
    if r.returncode != 0:
        raise BlueError('gh pr create failed')
    return r.stdout.strip()


def read_denials(path: Path) -> dict[str, int]:
    counts: dict[str, int] = {}
    if not path.exists():
        return counts
    for line in path.read_text(encoding='utf-8').splitlines():
        try:
            reason = json.loads(line).get('reason', 'unknown')
        except (json.JSONDecodeError, AttributeError):
            reason = 'unparseable'
        counts[reason] = counts.get(reason, 0) + 1
    return counts


# -- one round ---------------------------------------------------------------


@dataclass
class RoundOutcome:
    round: int
    ok: bool
    attempts: list[AgentRun]
    check: CheckResult | None
    commit: str | None = None
    fixed: int = 0
    picked: int = 0
    heldout_p99_us: int | None = None
    pr_url: str | None = None
    denials: dict[str, int] = field(default_factory=dict)
    problems: list[str] = field(default_factory=list)

    def summary(self) -> dict[str, object]:
        """Payload-free summary for the audit log and the PR body."""
        judged = self.check.judgments if self.check else {}
        return {
            'round': self.round,
            'ok': self.ok,
            'picked': self.picked,
            'fixed': self.fixed,
            'commit': self.commit,
            'models': [a.model for a in self.attempts],
            'minutes': round(sum(a.minutes for a in self.attempts), 1),
            'tool_calls': sum(a.tool_calls for a in self.attempts),
            'timed_out': any(a.timed_out for a in self.attempts),
            'rules_lines': self.check.rules_lines if self.check else 0,
            'cases_added': self.check.cases_added if self.check else 0,
            'heldout_p99_us': self.heldout_p99_us,
            'judgments': {
                k: sum(1 for v in judged.values() if v == k)
                for k in ('equivalent', 'not_equivalent', 'unsure')
            },
            'denials': self.denials,
            'problems': self.problems,
        }


Scorer = Callable[[Sequence[Variant], str], list[EngineVerdict]]
HeldoutP99 = Callable[[str], int | None]


def run_round(
    run: RunStore,
    round_: int,
    *,
    base: str = 'dev',
    pw_bin: Path,
    rescore: Scorer,
    heldout_p99: HeldoutP99 | None = None,
    budget_us: int = 1000,
    models: Sequence[str] = BLUE_MODELS,
    attempts: int = BLUE_MAX_ATTEMPTS,
    open_pr: bool = False,
    repo: Path = REPO_ROOT,
    keep_worktree: bool = False,
    opencode: str = 'opencode',
    worktree_root: Path | None = None,
    run_checks: Runner | None = _run_check,
) -> RoundOutcome:
    """§5.5 end to end. ``open_pr=False`` stops after the local commit."""
    picked = select_bypasses(
        run.variants(), run.verdicts(), run.syntax(), run.seeds()
    )
    outcome = RoundOutcome(round_, False, [], None, picked=len(picked))
    if not picked:
        outcome.problems.append('no train bypasses to fix')
        return outcome
    wt = create_worktree(round_, base, repo, worktree_root)
    denials = run.dir / f'blue-r{round_}-denials.jsonl'
    try:
        write_handoff(wt, picked, run.run_id)
        install_plugin(wt)
        feedback = None
        model_i = 0
        for attempt in range(1, attempts + 1):
            model = models[min(model_i, len(models) - 1)]
            agent = run_agent(
                wt,
                task_prompt(round_, len(picked), feedback),
                model,
                pw_bin=pw_bin,
                log=run.dir / f'blue-r{round_}-a{attempt}.jsonl',
                denials=denials,
                opencode=opencode,
            )
            outcome.attempts.append(agent)
            check = check_round(wt, base, run_checks=run_checks)
            outcome.check = check
            if check.ok:
                break
            if check.changed == [] and model_i + 1 < len(models):
                model_i += 1  # produced nothing: try the next free model
            feedback = check.feedback()
        outcome.denials = read_denials(denials)
        if not outcome.check or not outcome.check.ok:
            outcome.problems = outcome.check.problems if outcome.check else []
            return outcome

        sha = commit_round(
            wt, round_, f'fix(rules): red-team round {round_} bypasses'
        )
        outcome.commit = sha
        skip = {
            vid
            for vid, verdict in outcome.check.judgments.items()
            if verdict == 'not_equivalent'
        }
        targets = [v for v, _ in picked if v.id not in skip]
        after = rescore(targets, sha)
        outcome.fixed = sum(1 for x in after if x.outcome == 'blocked')
        if outcome.fixed == 0:
            outcome.problems.append('no train bypass is blocked after the fix')
        if heldout_p99 is not None:
            outcome.heldout_p99_us = heldout_p99(sha)
            p99 = outcome.heldout_p99_us
            if p99 is not None and p99 > budget_us:
                outcome.problems.append(
                    f'heldout p99 {p99} us exceeds the {budget_us} us budget'
                )
        outcome.ok = not outcome.problems
        if outcome.ok and open_pr:
            outcome.pr_url = push_and_open_pr(
                wt,
                round_,
                f'fix(rules): red-team round {round_} bypasses',
                pr_body(outcome),
                base,
            )
        return outcome
    finally:
        if not keep_worktree:
            remove_worktree(wt, repo)


def pr_body(outcome: RoundOutcome) -> str:
    s = outcome.summary()
    j = s['judgments']
    eq = f"{j['equivalent']} / {j['not_equivalent']} / {j['unsure']}"
    return f"""Automated blue-team patch for red-team round {s['round']}
(docs/plan/phase-5.md §5.5). Draft: needs human review before merge.

| | |
|---|---|
| train bypasses given | {s['picked']} |
| blocked after this patch | {s['fixed']} |
| equivalent / not equivalent / unsure | {eq} |
| rule lines changed | {s['rules_lines']} |
| corpus cases added | {s['cases_added']} |
| heldout p99 | {s['heldout_p99_us']} us |
| model(s) | {', '.join(s['models'])} |
| time / tool calls | {s['minutes']} min / {s['tool_calls']} |
| policy denials | {s['denials'] or 'none'} |

Reviewer checklist: the new rules are data-only and match the intent of the
bypasses (not just their exact text); the must-not-match cases are realistic;
spot-check the equivalence verdicts (§5.3.5).

🤖 Generated with [Claude Code](https://claude.com/claude-code)
"""


__all__ = [
    'RoundOutcome',
    'pr_body',
    'run_round',
    'AgentRun',
    'BLUE_MODELS',
    'BlueError',
    'CheckResult',
    'RunStore',
    'check_round',
    'commit_round',
    'create_worktree',
    'install_plugin',
    'push_and_open_pr',
    'read_denials',
    'remove_worktree',
    'run_agent',
    'select_bypasses',
    'task_prompt',
    'write_handoff',
]
