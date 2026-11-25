"""Score payloads with the engine at a given git rev (phase-5.md §5.4).

For each commit: a ``git worktree`` under ``redteam/.cache/worktrees/``,
``maturin build --release`` of ``crates/py``, the wheel cached by commit SHA
in ``redteam/.cache/wheels/<sha>/``, and a venv per SHA in
``redteam/.cache/venvs/<sha>/``. Scoring runs a small worker in that venv:
payloads go in over stdin as ``parts`` (JSONL), verdicts come back (JSONL),
so different versions never share a process.

``score_current()`` is the fast path for tests and smoke runs: it builds the
working tree instead of a worktree.

The worker only calls ``paste_warden.analyze``; payloads are never executed.
"""

from __future__ import annotations

import json
import math
import os
import shutil
import subprocess
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

from redteam.models import EngineVerdict, Seed, Variant
from redteam.store import to_parts

REDTEAM_DIR = Path(__file__).resolve().parents[2]
REPO_ROOT = REDTEAM_DIR.parent
CACHE_DIR = REDTEAM_DIR / '.cache'

MATURIN_SPEC = 'maturin>=1.9,<2'
BUILD_TIMEOUT_S = 1800
SCORE_TIMEOUT_S = 1800
WORKER_LOCALE = 'en'

# Runs inside the per-SHA venv with `python -I -c`. Reads {"id", "parts"}
# lines, writes one verdict line per input; never echoes the payload.
WORKER_SRC = r"""
import json, sys, time
for p in sys.argv[1:]:
    sys.path.insert(0, p)
import paste_warden
out = sys.stdout
for line in sys.stdin:
    if not line.strip():
        continue
    item = json.loads(line)
    text = ''.join(item['parts'])
    try:
        t0 = time.perf_counter_ns()
        r = paste_warden.analyze(text, LOCALE)
        dt = (time.perf_counter_ns() - t0) // 1000
    except Exception as e:
        out.write(json.dumps({'id': item['id'], 'error': type(e).__name__}))
        out.write('\n')
        continue
    cmd = r.get('command') or {}
    hidden = r.get('hidden') or {}
    reasons = [x['id'] for x in cmd.get('reasons', [])]
    reasons += [x['id'] for x in hidden.get('reasons', [])]
    out.write(json.dumps({
        'id': item['id'],
        'action': r['action'],
        'level': cmd.get('level', 'none'),
        'risk_score': int(cmd.get('risk_score', 0)),
        'reason_ids': reasons,
        'duration_us': int(dt),
        'engine_version': paste_warden.ENGINE_VERSION,
    }))
    out.write('\n')
out.flush()
""".replace('LOCALE', repr(WORKER_LOCALE))


class EngineError(RuntimeError):
    """Building or running the engine failed (no payload in the message)."""


@dataclass(frozen=True)
class EngineBuild:
    rules_rev: str
    python: Path
    # Extra sys.path entries for the worker (tests use a stub module).
    extra_path: tuple[str, ...] = ()


def _run(
    argv: Sequence[str],
    cwd: Path | None = None,
    redact: bool = False,
    **kw,
) -> str:
    """Run a process. ``redact``: never put its stderr in the error (the
    worker's stderr could echo input)."""
    try:
        p = subprocess.run(
            list(argv),
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=kw.pop('timeout', BUILD_TIMEOUT_S),
            check=False,
            **kw,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        raise EngineError(f'{argv[0]}: {type(e).__name__}') from None
    if p.returncode != 0:
        name = Path(argv[0]).name
        if redact:
            raise EngineError(f'{name} exited with {p.returncode}')
        tail = p.stderr.strip().splitlines()[-5:]
        raise EngineError(f'{name} {argv[1:3]} failed: {" / ".join(tail)}')
    return p.stdout


def resolve_rev(rev: str, repo: Path = REPO_ROOT) -> str:
    return _run(
        ['git', 'rev-parse', '--verify', f'{rev}^{{commit}}'], repo
    ).strip()


def _uv() -> str:
    uv = shutil.which('uv')
    if uv is None:
        raise EngineError('uv not found on PATH')
    return uv


def build_wheel(source: Path, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    # Share compiled dependencies between revisions.
    env.setdefault('CARGO_TARGET_DIR', str(CACHE_DIR / 'target'))
    _run(
        [
            _uv(),
            'tool',
            'run',
            '--from',
            MATURIN_SPEC,
            'maturin',
            'build',
            '--release',
            '--quiet',
            '-m',
            str(source / 'crates' / 'py' / 'Cargo.toml'),
            '-o',
            str(out_dir),
        ],
        cwd=source,
        env=env,
    )
    wheels = sorted(out_dir.glob('paste_warden-*.whl'))
    if not wheels:
        raise EngineError('maturin produced no wheel')
    return wheels[-1]


def make_venv(venv: Path, wheel: Path) -> Path:
    python = venv / 'bin' / 'python'
    if not python.exists():
        _run([_uv(), 'venv', '--quiet', '--python', sys.executable, str(venv)])
    _run(
        [
            _uv(),
            'pip',
            'install',
            '--quiet',
            '--reinstall',
            '--python',
            str(python),
            str(wheel),
        ]
    )
    return python


def prepare(rev: str, repo: Path = REPO_ROOT, cache: Path = CACHE_DIR):
    """Build (or reuse) the engine at ``rev``. Returns an ``EngineBuild``."""
    sha = resolve_rev(rev, repo)
    wheel_dir = cache / 'wheels' / sha
    venv = cache / 'venvs' / sha
    python = venv / 'bin' / 'python'
    wheels = sorted(wheel_dir.glob('paste_warden-*.whl'))
    if not wheels:
        worktree = cache / 'worktrees' / sha
        if not worktree.exists():
            worktree.parent.mkdir(parents=True, exist_ok=True)
            _run(
                ['git', 'worktree', 'add', '--detach', str(worktree), sha],
                repo,
            )
        try:
            wheels = [build_wheel(worktree, wheel_dir)]
        finally:
            _run(['git', 'worktree', 'remove', '--force', str(worktree)], repo)
        if python.exists():
            shutil.rmtree(venv)
    if not python.exists():
        make_venv(venv, wheels[-1])
    return EngineBuild(rules_rev=sha, python=python)


def prepare_current(repo: Path = REPO_ROOT, cache: Path = CACHE_DIR):
    """Build the working tree (uncommitted changes included)."""
    sha = resolve_rev('HEAD', repo)
    dirty = bool(_run(['git', 'status', '--porcelain'], repo).strip())
    wheel_dir = cache / 'wheels' / 'working'
    for old in wheel_dir.glob('*.whl'):
        old.unlink()
    wheel = build_wheel(repo, wheel_dir)
    python = make_venv(cache / 'venvs' / 'working', wheel)
    return EngineBuild(
        rules_rev=sha + ('-dirty' if dirty else ''), python=python
    )


Scorable = Variant | Seed | tuple[str, str]


def _item(x: Scorable) -> tuple[str, str]:
    if isinstance(x, Variant):
        return x.id, x.payload
    if isinstance(x, Seed):
        return x.case_id, x.payload
    return x


def score(items: Iterable[Scorable], build: EngineBuild) -> list[EngineVerdict]:
    """Analyze each payload in the worker; one verdict per input, in order.

    ``items`` are Variants, Seeds or ``(id, text)`` pairs (benign samples).
    """
    pairs = [_item(x) for x in items]
    if not pairs:
        return []
    stdin = ''.join(
        json.dumps({'id': i, 'parts': to_parts(t)}, ensure_ascii=True) + '\n'
        for i, t in pairs
    )
    out = _run(
        [str(build.python), '-I', '-c', WORKER_SRC, *build.extra_path],
        input=stdin,
        redact=True,
        timeout=SCORE_TIMEOUT_S,
    )
    by_id: dict[str, dict] = {}
    for line in out.splitlines():
        if line.strip():
            r = json.loads(line)
            by_id[r['id']] = r
    verdicts = []
    for i, _ in pairs:
        r = by_id.get(i)
        if r is None or 'error' in r:
            kind = 'missing' if r is None else r['error']
            raise EngineError(f'worker failed on item {i}: {kind}')
        verdicts.append(
            EngineVerdict(
                variant_id=i,
                rules_rev=build.rules_rev,
                action=r['action'],
                level=r['level'],
                risk_score=r['risk_score'],
                reason_ids=tuple(r['reason_ids']),
                duration_us=r['duration_us'],
            )
        )
    return verdicts


def score_at(rev: str, items: Iterable[Scorable]) -> list[EngineVerdict]:
    return score(items, prepare(rev))


def score_current(items: Iterable[Scorable]) -> list[EngineVerdict]:
    return score(items, prepare_current())


def percentile(values: Sequence[int], q: float) -> int:
    """Nearest-rank percentile (q in [0, 100]); 0 for an empty list."""
    if not values:
        return 0
    ordered = sorted(values)
    rank = max(1, math.ceil(q / 100 * len(ordered)))
    return ordered[rank - 1]


def latency(verdicts: Iterable[EngineVerdict]) -> dict[str, int]:
    durations = [v.duration_us for v in verdicts]
    return {
        'n': len(durations),
        'p50_us': percentile(durations, 50),
        'p99_us': percentile(durations, 99),
        'max_us': max(durations, default=0),
    }
