"""Blue-team orchestrator (phase-5.md §5.5) against a throwaway git repo.

A fake ``opencode`` script plays the agent, so nothing here touches the
network, a model, or the real repository.
"""

import json
import stat
import subprocess

import pytest

from redteam.blue import orchestrator as o
from redteam.models import EngineVerdict, Seed, Shell, SyntaxVerdict, Variant
from redteam.store import RunStore

MARK = 'PW' + 'MARKER' + 'XYZZY'


def git(*args, cwd):
    subprocess.run(
        ['git', *args], cwd=cwd, check=True, capture_output=True, text=True
    )


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / 'repo'
    for d in ('rules', 'corpus/cases', 'crates/core', 'redteam/eval'):
        (r / d).mkdir(parents=True)
    (r / 'rules/a.json').write_text('{"k": []}\n')
    (r / 'corpus/cases/x.jsonl').write_text('{"id": "x.1"}\n')
    (r / 'crates/core/lib.rs').write_text('// core\n')
    (r / 'redteam/eval/heldout.jsonl').write_text('{"secret": "heldout"}\n')
    git('init', '-q', '-b', 'main', cwd=r)
    git('-c', 'user.name=t', '-c', 'user.email=t@example.invalid',
        'add', '-A', cwd=r)  # fmt: skip
    git('-c', 'user.name=t', '-c', 'user.email=t@example.invalid',
        'commit', '-qm', 'init', cwd=r)  # fmt: skip
    return r


def variant(i, seed='s-train', tech=('cmd.caret',), gen='g0', shell=Shell.CMD):
    return Variant(
        id=f'v{i}',
        seed_id=seed,
        round=1,
        generator=gen,
        techniques=tech,
        shell=shell,
        payload=f'echo {MARK} {i}',
    )


def verdict(i, action='allow', reasons=()):
    return EngineVerdict(
        variant_id=f'v{i}',
        rules_rev='r',
        action=action,
        level='none',
        risk_score=0,
        reason_ids=reasons,
        duration_us=5,
    )


SEEDS = [
    Seed(case_id='s-train', shell=Shell.CMD, split='train', payload='a'),
    Seed(case_id='s-held', shell=Shell.CMD, split='heldout', payload='b'),
]
OK = SyntaxVerdict(shell=Shell.CMD, status='ok')
BAD = SyntaxVerdict(shell=Shell.CMD, status='invalid')


def test_select_train_valid_unblocked_round_robin():
    vs = [
        variant(1),
        variant(2),
        variant(3, tech=('cmd.set',)),
        variant(4, seed='s-held'),
        variant(5),
        variant(6),
    ]
    vds = [
        verdict(1),
        verdict(2),
        verdict(3),
        verdict(4),
        verdict(5, action='quarantine'),
        verdict(6),
    ]
    syn = {v.id: OK for v in vs} | {'v6': BAD}
    picked = o.select_bypasses(vs, vds, syn, SEEDS, limit=2)
    ids = [v.id for v, _ in picked]
    # v4 heldout, v5 blocked, v6 invalid; round-robin across 2 clusters.
    assert sorted(ids) == ['v1', 'v3']
    assert {v.id for v, _ in o.select_bypasses(vs, vds, syn, SEEDS)} == {
        'v1',
        'v2',
        'v3',
    }


def test_select_covers_every_generator_and_shell_not_the_alphabet():
    # Many G1 clusters whose names sort first ('alias…') must not crowd out
    # G0 or other shells (rounds 1-2 only ever picked G1 'a'/'b' names).
    vs = [variant(i, tech=(f'a{i:02d}',), gen='g1') for i in range(20)]
    vs += [variant(100 + i, tech=('sh.ifs',), shell=Shell.SH) for i in range(5)]
    vs += [variant(200, tech=('sh.quote_split',), shell=Shell.SH)]
    vs += [variant(300, tech=('ps.reverse',), shell=Shell.POWERSHELL)]
    syn = {v.id: OK for v in vs}
    picked = o.select_bypasses(
        vs, [verdict(int(v.id[1:])) for v in vs], syn, SEEDS, limit=4
    )
    lanes = {(str(v.generator), str(v.shell)) for v, _ in picked}
    assert lanes == {('g0', 'sh'), ('g0', 'powershell'), ('g1', 'cmd')}
    # Inside the sh lane the bigger cluster (sh.ifs, 5 samples) goes first.
    sh = [v for v, _ in picked if v.shell == Shell.SH]
    assert sh[0].techniques == ('sh.ifs',)


def test_stale_round_branch_is_replaced_but_work_is_kept(repo, tmp_path):
    # A failed round leaves an empty branch behind: the rerun replaces it.
    git('branch', 'redteam/round-1', cwd=repo)
    wt = o.create_worktree(1, 'main', repo, tmp_path / 'wts')
    (wt / 'rules/a.json').write_text('{"k": [1]}\n')
    git('-c', 'user.name=t', '-c', 'user.email=t@example.invalid',
        'commit', '-qam', 'work', cwd=wt)  # fmt: skip
    o.remove_worktree(wt, repo)
    # A branch with commits of its own is never deleted.
    with pytest.raises(o.BlueError, match='commit'):
        o.create_worktree(1, 'main', repo, tmp_path / 'wts')
    assert 'redteam/round-1' in o._git(['branch', '--list'], repo)


def test_worktree_is_sparse_and_handoff_holds_only_parts(repo, tmp_path):
    wt = o.create_worktree(1, 'main', repo, tmp_path / 'wts')
    try:
        assert not (wt / 'redteam').exists()
        assert (wt / 'rules/a.json').exists()
        o.write_handoff(wt, [(variant(1), verdict(1))], 'run-1')
        o.install_plugin(wt)
        for f in (wt / '.pw-blue').rglob('*'):
            if f.is_file():
                assert MARK not in f.read_text()
        line = (wt / '.pw-blue/blue-input.jsonl').read_text()
        assert ''.join(json.loads(line)['parts']).startswith('echo ')
        assert (wt / '.opencode/plugins/pw-blue-guard.ts').exists()
        cfg = json.loads((wt / '.opencode/opencode.json').read_text())
        assert o.BLUE_MODELS[0].startswith('ollama/')
        model = o.BLUE_MODELS[0].split('/', 1)[1]
        assert model in cfg['provider']['ollama']['models']
        limit = cfg['provider']['ollama']['models'][model]['limit']
        assert limit['output'] == o.OLLAMA_MAX_OUTPUT_TOKENS
        assert limit['context'] >= limit['output']
        assert cfg['permission']['webfetch'] == 'deny'
        # Hand-off and plugin are git-excluded, so the diff stays clean.
        o.stage_all(wt)
        assert o.changed_files(wt, 'main') == []
    finally:
        o.remove_worktree(wt, repo)


def _good_change(wt):
    with (wt / 'rules/a.json').open('w') as f:
        f.write('{"k": ["new"]}\n')
    cases = wt / 'corpus/cases'
    (cases / 'redteam-r1.jsonl').write_text(
        json.dumps({'id': 'c1', 'expect': {'level': 'malicious'}}) + '\n'
    )
    (cases / 'redteam-r1-benign.jsonl').write_text(
        json.dumps({'id': 'c2', 'expect': {'level': 'none'}}) + '\n'
    )


@pytest.mark.parametrize(
    'mutate, problem',
    [
        (lambda wt: None, 'no changes'),
        (
            lambda wt: (wt / 'crates/core/lib.rs').write_text('// x\n'),
            'outside rules/',
        ),
        (
            lambda wt: (wt / 'corpus/cases/x.jsonl').write_text(''),
            'existing corpus lines',
        ),
        (
            lambda wt: (wt / 'rules/a.json').write_text('{"k": [1]}\n'),
            'must-match',
        ),
    ],
)
def test_check_round_rejects(repo, tmp_path, mutate, problem):
    wt = o.create_worktree(1, 'main', repo, tmp_path / 'wts')
    try:
        mutate(wt)
        result = o.check_round(wt, 'main', run_checks=None)
        assert not result.ok
        assert any(problem in p for p in result.problems), result.problems
    finally:
        o.remove_worktree(wt, repo)


def test_check_round_accepts_data_only_change(repo, tmp_path):
    wt = o.create_worktree(1, 'main', repo, tmp_path / 'wts')
    try:
        _good_change(wt)
        calls = []
        result = o.check_round(
            wt, 'main', run_checks=lambda c, cwd: calls.append(c) or 0
        )
        assert result.ok, result.problems
        assert result.cases_added == 2 and result.rules_lines == 2
        assert len(calls) == len(o.CHECK_COMMANDS)
        failing = o.check_round(wt, 'main', run_checks=lambda c, cwd: 1)
        assert not failing.ok and 'failed' in failing.problems[0]
    finally:
        o.remove_worktree(wt, repo)


FAKE_AGENT = """#!/bin/sh
# Fake opencode: behaves like a well-behaved blue agent.
test -n "$PW_BLUE_ROOT" || exit 9
printf '{"k": ["fixed"]}\\n' > rules/a.json
printf '{"id":"c1","expect":{"level":"malicious"}}\\n' \\
  > corpus/cases/redteam-r1.jsonl
printf '{"id":"c2","expect":{"level":"none"}}\\n' \\
  > corpus/cases/redteam-r1-benign.jsonl
printf '{"judgments":[{"variant_id":"v2","verdict":"not_equivalent"}]}' \\
  > .pw-blue/blue-output.json
echo '{"type":"tool_use"}'
echo '{"type":"tool_use"}'
"""


def _store(tmp_path):
    run = RunStore('run-1', root=tmp_path / 'runs').create()
    run.add_seeds(SEEDS)
    run.add_variants([variant(1), variant(2, tech=('cmd.set',))])
    run.add_syntax([('v1', OK), ('v2', OK)])
    run.add_verdicts([verdict(1), verdict(2)])
    return run


def _fake(tmp_path, body):
    fake = tmp_path / 'opencode'
    fake.write_text(body)
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    return str(fake)


def test_run_round_end_to_end_without_network(repo, tmp_path):
    run = _store(tmp_path)
    seen = {}

    def rescore(variants, sha):
        seen['ids'] = [v.id for v in variants]
        seen['sha'] = sha
        return [verdict(int(v.id[1:]), action='quarantine') for v in variants]

    out = o.run_round(
        run,
        1,
        base='main',
        pw_bin=tmp_path / 'paste-warden',
        rescore=rescore,
        heldout_p99=lambda sha: 400,
        repo=repo,
        opencode=_fake(tmp_path, FAKE_AGENT),
        worktree_root=tmp_path / 'wts',
        run_checks=lambda c, cwd: 0,
    )
    assert out.ok, out.problems
    assert out.fixed == 1 and seen['ids'] == ['v1']  # v2 judged not equal
    assert out.summary()['tool_calls'] == 2
    log = subprocess.run(
        ['git', 'log', '--format=%s', '-1', 'redteam/round-1'],
        cwd=repo,
        capture_output=True,
        text=True,
    ).stdout
    assert 'round 1' in log
    files = subprocess.run(
        ['git', 'show', '--name-only', '--format=', 'redteam/round-1'],
        cwd=repo,
        capture_output=True,
        text=True,
    ).stdout.split()
    assert sorted(files) == [
        'corpus/cases/redteam-r1-benign.jsonl',
        'corpus/cases/redteam-r1.jsonl',
        'rules/a.json',
    ]
    body = o.pr_body(out)
    assert MARK not in body and MARK not in json.dumps(out.summary())


def test_run_round_reports_budget_and_unfixed(repo, tmp_path):
    out = o.run_round(
        _store(tmp_path),
        1,
        base='main',
        pw_bin=tmp_path / 'paste-warden',
        rescore=lambda vs, sha: [verdict(int(v.id[1:])) for v in vs],
        heldout_p99=lambda sha: 5000,
        repo=repo,
        opencode=_fake(tmp_path, FAKE_AGENT),
        worktree_root=tmp_path / 'wts',
        run_checks=lambda c, cwd: 0,
    )
    assert not out.ok
    assert any('no train bypass' in p for p in out.problems)
    assert any('budget' in p for p in out.problems)


def test_misbehaving_agent_is_rejected_after_retries(repo, tmp_path):
    bad = '#!/bin/sh\nprintf "// pwned\\n" > crates/core/lib.rs\n'
    out = o.run_round(
        _store(tmp_path),
        1,
        base='main',
        pw_bin=tmp_path / 'paste-warden',
        rescore=lambda vs, sha: [],
        repo=repo,
        opencode=_fake(tmp_path, bad),
        worktree_root=tmp_path / 'wts',
        run_checks=lambda c, cwd: 0,
    )
    assert not out.ok and out.commit is None
    assert len(out.attempts) == o.BLUE_MAX_ATTEMPTS
    assert any('outside rules/' in p for p in out.problems)


def test_prompt_names_files_not_payloads():
    p = o.task_prompt(3, 7, feedback='- x failed')
    assert 'redteam-r3' in p and 'x failed' in p and MARK not in p
