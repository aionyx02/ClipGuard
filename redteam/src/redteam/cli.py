"""``redteam`` command line (docs/plan/phase-5.md §5.3.1).

Every subcommand prints counts only, never payload text (§5.3.4).

    redteam seeds
    redteam attack  --run-id R --round N --rev REV [--split train|heldout]
                    [--seed-limit K] [--run-seed S]
    redteam freeze  --run-id R            # heldout run -> redteam/eval/
    redteam eval    --label V1 --rev REV  # heldout + benign at REV
    redteam blue    --run-id R --round N [--base dev] [--open-pr]
    redteam report  --out DIR --version V1=REV ... [--round N=RUN ...]
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

SUBCOMMANDS = ('seeds', 'attack', 'freeze', 'eval', 'blue', 'report')

EVAL_HELDOUT = 'heldout.jsonl'
EVAL_BENIGN_EXTRA = 'benign-extra.jsonl'


def refuse_windows(platform: str | None = None) -> str | None:
    """S8: on Windows, a UNC `using module` may reach SMB at parse time."""
    platform = sys.platform if platform is None else platform
    if platform.startswith('win'):
        return 'redteam runs on macOS or Linux only (phase-5.md §5.3.4)'
    return None


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec='seconds')


def _print(obj: object) -> None:
    print(json.dumps(obj, ensure_ascii=False, sort_keys=True))


# -- seeds ---------------------------------------------------------------------


def cmd_seeds(_: argparse.Namespace) -> int:
    from redteam.seeds import SeedStats, load_seeds

    stats = SeedStats()
    seeds = load_seeds(stats=stats)
    _print(
        {
            'seeds': len(seeds),
            'by_shell': dict(Counter(s.shell.value for s in seeds)),
            'by_split': dict(Counter(s.split for s in seeds)),
        }
    )
    return 0


def unchecked_if_too_large(verdict):
    """Padding variants deliberately exceed the validator's input cap (they
    probe the engine's read limit). Their syntax is the seed's plus
    whitespace, so report them as ``unchecked`` rather than a crash."""
    ids = {e.id for e in verdict.errors}
    if verdict.status == 'validator_crash' and ids == {'payload-too-large'}:
        return verdict.model_copy(update={'status': 'unchecked', 'errors': ()})
    return verdict


def usable_syntax(verdict) -> bool:
    return verdict.ok or verdict.status == 'unchecked'


# -- attack --------------------------------------------------------------------


def cmd_attack(a: argparse.Namespace) -> int:
    from redteam import engine
    from redteam.audit import AuditLog
    from redteam.models import AuditEvent
    from redteam.mutate import generate_g0
    from redteam.seeds import heldout, load_seeds, train
    from redteam.store import RunStore
    from redteam.validate import Validator

    seeds = load_seeds()
    pool = train(seeds) if a.split == 'train' else heldout(seeds)
    if a.seed_limit:
        pool = pool[: a.seed_limit]
    run = RunStore(a.run_id).create()
    audit = AuditLog(run.audit_path)
    run.add_seeds(pool)

    t0 = time.monotonic()
    with Validator() as validator:
        # A seed that does not parse in its own shell (e.g. a markdown-escape
        # case) cannot yield valid variants: skip it and count it.
        seed_ok = {
            s.case_id: usable_syntax(
                unchecked_if_too_large(validator.validate(s.payload, s.shell))
            )
            for s in pool
        }
        usable = [s for s in pool if seed_ok[s.case_id]]
        variants = generate_g0(usable, run_seed=a.run_seed, round=a.round)
        run.add_variants(variants)
        syntax = [
            (
                v.id,
                unchecked_if_too_large(validator.validate(v.payload, v.shell)),
            )
            for v in variants
        ]
    run.add_syntax(syntax)
    build = engine.prepare(a.rev)
    verdicts = engine.score(variants, build)
    run.add_verdicts(verdicts)
    g1 = None
    if a.g1:
        g1 = _attack_g1(a, usable, run, audit, build)
        variants = [*variants, *g1.variants]
        syntax = [*syntax, *g1.syntax.items()]
        verdicts = [*verdicts, *g1.verdicts.values()]

    by_syntax = Counter(s.status for _, s in syntax)
    by_outcome = Counter(v.outcome for v in verdicts)
    audit.append(
        AuditEvent(
            ts=_now(),
            run_id=run.run_id,
            round=a.round,
            actor='orchestrator',
            event='attack',
            rules_rev=build.rules_rev,
            params={'split': a.split, 'run_seed': a.run_seed, 'g0': True},
            result={
                'seeds': len(pool),
                'seeds_invalid': len(pool) - len(usable),
                'variants': len(variants),
                'syntax': dict(by_syntax),
                'outcome': dict(by_outcome),
            },
            duration_ms=int((time.monotonic() - t0) * 1000),
        )
    )
    _print(
        {
            'run_id': run.run_id,
            'rules_rev': build.rules_rev,
            'seeds': len(pool),
            'seeds_invalid': len(pool) - len(usable),
            'variants': len(variants),
            'syntax': dict(by_syntax),
            'outcome': dict(by_outcome),
            'latency_us': engine.latency(verdicts),
            'g1': _g1_summary(g1),
        }
    )
    return 0


def _attack_g1(a, seeds, run, audit, build):
    """G1 against the same engine build as G0 (§5.3.3)."""
    from redteam import engine
    from redteam.gen_llm import G1_FALLBACK_MODELS, ChatClient, generate_g1
    from redteam.validate import Validator

    def scorer(items):
        return engine.score(items, build)

    with ChatClient(model=a.g1_model) as client, Validator() as validator:
        result = generate_g1(
            seeds,
            run_seed=a.run_seed,
            round=a.round,
            client=client,
            scorer=scorer,
            validator=validator,
            audit=audit,
            run_id=run.run_id,
            fallback_models=G1_FALLBACK_MODELS,
            attempts=a.g1_attempts,
        )
    run.add_variants(result.variants)
    run.add_syntax(result.syntax.items())
    run.add_verdicts(result.verdicts.values())
    return result


def _g1_summary(result) -> dict[str, object] | None:
    if result is None:
        return None
    st = result.stats
    return {
        'models': result.models,
        'calls': st.calls,
        'refused': st.refused,
        'invalid_output': st.invalid_output,
        'variants': st.variants,
        'outcomes': {k: dict(v) for k, v in st.outcomes.items()},
    }


# -- freeze --------------------------------------------------------------------


def cmd_freeze(a: argparse.Namespace) -> int:
    """Heldout seeds + their syntax-valid variants -> redteam/eval/."""
    from redteam.store import EVAL_DIR, RunStore, write_eval

    run = RunStore(a.run_id)
    seeds = [s for s in run.seeds() if s.split == 'heldout']
    if not seeds or len(seeds) != len(run.seeds()):
        print('freeze needs a run made with --split heldout', file=sys.stderr)
        return 3
    syntax = run.syntax()
    keep = [
        v
        for v in run.variants()
        if syntax.get(v.id) and usable_syntax(syntax[v.id])
    ]
    out = Path(a.out) if a.out else EVAL_DIR / EVAL_HELDOUT
    if out.exists() and not a.force:
        print(f'{out.name} exists; pass --force to replace it', file=sys.stderr)
        return 3
    n = write_eval(out, [*seeds, *keep])
    _print(
        {'file': out.name, 'seeds': len(seeds), 'variants': len(keep), 'n': n}
    )
    return 0


# -- eval ----------------------------------------------------------------------


def _benign_corpus() -> list[tuple[str, str]]:
    from redteam.seeds import CORPUS_DIR, resolve_text

    out = []
    for path in sorted((CORPUS_DIR / 'benign').glob('*.jsonl')):
        for line in path.read_text(encoding='utf-8').splitlines():
            if line.strip():
                case = json.loads(line)
                out.append((case['id'], resolve_text(case['input'])))
    return out


def evaluate(label: str, rev: str, eval_dir: Path) -> dict[str, object]:
    """Score the frozen heldout and both benign sets at ``rev``."""
    from redteam import engine
    from redteam.store import BenignItem, read_eval

    items = read_eval(eval_dir / EVAL_HELDOUT)
    malicious = [x for x in items if not isinstance(x, BenignItem)]
    extra_path = eval_dir / EVAL_BENIGN_EXTRA
    extra = [
        (x.id, x.text)
        for x in (read_eval(extra_path) if extra_path.exists() else [])
        if isinstance(x, BenignItem)
    ]
    build = engine.prepare(rev)
    return {
        'label': label,
        'rules_rev': build.rules_rev,
        'malicious': engine.score(malicious, build),
        'benign_corpus': engine.score(_benign_corpus(), build),
        'benign_extra': engine.score(extra, build),
        'items': malicious,
    }


def cmd_eval(a: argparse.Namespace) -> int:
    from redteam.store import EVAL_DIR, RUNS_DIR

    res = evaluate(a.label, a.rev, Path(a.eval_dir) if a.eval_dir else EVAL_DIR)
    out = RUNS_DIR / f'eval-{a.label}'
    out.mkdir(parents=True, exist_ok=True)
    summary = {'label': a.label, 'rules_rev': res['rules_rev']}
    for key in ('malicious', 'benign_corpus', 'benign_extra'):
        verdicts = res[key]
        (out / f'{key}.jsonl').write_text(
            ''.join(v.model_dump_json() + '\n' for v in verdicts)
        )
        summary[key] = dict(Counter(v.action for v in verdicts))
    (out / 'rev').write_text(str(res['rules_rev']) + '\n')
    _print(summary)
    return 0


# -- blue ----------------------------------------------------------------------


def cmd_blue(a: argparse.Namespace) -> int:
    from redteam import engine
    from redteam.blue import orchestrator as o
    from redteam.store import EVAL_DIR, RunStore

    run = RunStore(a.run_id)
    pw_bin = Path(a.pw_bin).resolve()
    if not pw_bin.is_file():
        print('--pw-bin must point at a built paste-warden', file=sys.stderr)
        return 3

    def rescore(variants, sha):
        return engine.score(variants, engine.prepare(sha))

    def heldout_p99(sha):
        if not (EVAL_DIR / EVAL_HELDOUT).exists():
            return None
        res = evaluate('blue-check', sha, EVAL_DIR)
        small = [
            v
            for v, item in zip(res['malicious'], res['items'], strict=True)
            if len(item.payload.encode('utf-8')) <= 1024
        ]
        return engine.latency(small).get('p99')

    out = o.run_round(
        run,
        a.round,
        base=a.base,
        pw_bin=pw_bin,
        rescore=rescore,
        heldout_p99=heldout_p99,
        open_pr=a.open_pr,
    )
    summary = out.summary() | {'pr': out.pr_url}
    (run.dir / f'blue-r{a.round}-summary.json').write_text(
        json.dumps(summary, indent=2, sort_keys=True) + '\n'
    )
    _print(summary)
    return 0 if out.ok else 1


# -- report --------------------------------------------------------------------


def _scored(res: dict[str, object]):
    from redteam.report import join

    return join(res['items'], res['malicious'])


def cmd_report(a: argparse.Namespace) -> int:
    from redteam.report import (
        RoundInput,
        VersionInput,
        build_report,
        join,
        write_report,
    )
    from redteam.store import EVAL_DIR, RunStore

    versions = []
    for spec in a.version:
        label, _, rev = spec.partition('=')
        res = evaluate(label, rev, EVAL_DIR)
        versions.append(
            VersionInput(
                label=label,
                rules_rev=str(res['rules_rev']),
                items=tuple(_scored(res)),
                benign_corpus=tuple(v.action for v in res['benign_corpus']),
                benign_extra=tuple(v.action for v in res['benign_extra']),
            )
        )
    rounds = []
    for spec in a.round or ():
        n, _, run_id = spec.partition('=')
        run = RunStore(run_id)
        verdicts = run.verdicts()
        rev = verdicts[0].rules_rev if verdicts else ''
        rounds.append(
            RoundInput(
                round=int(n),
                version=rev,
                items=tuple(
                    join(run.variants(), verdicts, syntax=run.syntax())
                ),
            )
        )
    report = build_report(versions, rounds, generated_at=_now())
    paths = write_report(report, Path(a.out))
    _print({'out': str(a.out), 'files': [p.name for p in paths]})
    return 0


# -- main ----------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog='redteam')
    sub = p.add_subparsers(dest='command', required=True)
    sub.add_parser('seeds', help='seed statistics')

    at = sub.add_parser('attack', help='G0 variants -> validate -> score')
    at.add_argument('--run-id', required=True)
    at.add_argument('--round', type=int, required=True)
    at.add_argument('--rev', default='HEAD')
    at.add_argument('--split', choices=('train', 'heldout'), default='train')
    at.add_argument('--seed-limit', type=int, default=0)
    at.add_argument('--run-seed', type=int, default=20261125)
    at.add_argument('--g1', action='store_true', help='also run G1 (Ollama)')
    at.add_argument('--g1-model', default='qwen3.8:27b-mlx')
    # Heldout must not adapt to V1 (§5.2): use --g1-attempts 1 there.
    at.add_argument('--g1-attempts', type=int, default=3)

    fr = sub.add_parser('freeze', help='heldout run -> redteam/eval/')
    fr.add_argument('--run-id', required=True)
    fr.add_argument('--out')
    fr.add_argument('--force', action='store_true')

    ev = sub.add_parser('eval', help='score heldout + benign at a rev')
    ev.add_argument('--label', required=True)
    ev.add_argument('--rev', required=True)
    ev.add_argument('--eval-dir')

    bl = sub.add_parser('blue', help='one blue-team round (§5.5)')
    bl.add_argument('--run-id', required=True)
    bl.add_argument('--round', type=int, required=True)
    bl.add_argument('--base', default='dev')
    bl.add_argument('--pw-bin', default='../target/release/paste-warden')
    bl.add_argument('--open-pr', action='store_true')

    rp = sub.add_parser('report', help='four metrics and V1->V3 charts')
    rp.add_argument('--out', required=True)
    rp.add_argument('--version', action='append', required=True)
    rp.add_argument('--round', action='append')
    return p


HANDLERS = {
    'seeds': cmd_seeds,
    'attack': cmd_attack,
    'freeze': cmd_freeze,
    'eval': cmd_eval,
    'blue': cmd_blue,
    'report': cmd_report,
}


def main(argv: Sequence[str] | None = None) -> int:
    reason = refuse_windows()
    if reason:
        print(reason, file=sys.stderr)
        return 3
    args = build_parser().parse_args(argv)
    return HANDLERS[args.command](args)
