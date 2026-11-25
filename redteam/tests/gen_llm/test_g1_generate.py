import re
from pathlib import Path

import httpx
from g1_fakes import DIGEST, FakeOllama, FakeScorer, J, make_seeds
from g1_fakes import variants_json as vj

from redteam.audit import AuditLog, find_leaks
from redteam.gen_llm import generate_g1
from redteam.gen_llm.generate import g1_variant_id
from redteam.models import Shell, SyntaxIssue, SyntaxVerdict, sha256_hex

REF = f'primary:1b@{DIGEST[:12]}'
BYPASS = J('BYP', 'ASS_MARK')


def _always(*items):
    return lambda body, n: vj(*items)


def _numbered(body, n):
    # A fresh payload per request so nothing is dropped as a duplicate.
    return vj(('sh', f'echo v{n}a', 'quote'), ('sh', f'echo v{n}b', 'var'))


def test_one_attempt_builds_variants(tmp_path):
    seed = make_seeds()[1]
    fake = FakeOllama(_numbered)
    scorer = FakeScorer()
    res = generate_g1(
        [seed],
        run_seed=1,
        round=2,
        client=fake.client(),
        scorer=scorer,
        attempts=1,
    )
    assert res.stats.calls == 1
    assert len(res.variants) == 2
    v = res.variants[0]
    assert v.generator == 'g1' and v.round == 2
    assert v.seed_id == seed.case_id and v.parent_id is None
    assert v.model == REF
    assert v.techniques == ('quote',)
    assert v.shell is Shell.SH
    assert v.id == g1_variant_id(seed.case_id, 1, 0, sha256_hex('echo v0a'))
    assert res.models == [REF]
    assert res.stats.outcomes == {1: {'blocked': 2}}
    assert res.stats.techniques == {'quote': 1, 'var': 1}


def test_retry_with_feedback_until_bypass():
    seed = make_seeds()[0]

    def reply(body, n):
        if n < 2:
            return _numbered(body, n)
        return vj(('powershell', f'x {BYPASS}', 'concat'))

    fake = FakeOllama(reply)
    scorer = FakeScorer(bypass_marker=BYPASS)
    res = generate_g1(
        [seed], run_seed=1, round=1, client=fake.client(), scorer=scorer
    )
    assert res.stats.calls == 3
    prompts = fake.user_prompts()
    assert 'reason IDs' not in prompts[0]
    for p in prompts[1:]:
        assert 'cmd.fake-rule, ps.x' in p
        assert 'action=quarantine' in p
        # Feedback is the lowest-risk blocked variant (89 < 90).
        assert 'risk_score=89' in p
    # Feedback never quotes the rule text or the previous variant.
    assert 'echo v0' not in prompts[1]
    a1 = [v for v in res.variants if v.id.startswith('g1')][:2]
    a2 = res.variants[2:4]
    assert all(v.parent_id is None for v in a1)
    assert all(v.parent_id == a1[1].id for v in a2)
    assert res.stats.outcomes[3] == {'bypassed': 1}
    assert res.stats.seeds_evaded_at == {3: 1}
    # Per-request seed differs per attempt.
    assert len({r['seed'] for r in fake.requests}) == 3


def test_stop_after_first_bypass():
    fake = FakeOllama(_always(('sh', f'echo {BYPASS}', 'x')))
    res = generate_g1(
        make_seeds()[1:],
        run_seed=1,
        round=1,
        client=fake.client(),
        scorer=FakeScorer(bypass_marker=BYPASS),
    )
    assert res.stats.calls == 1
    assert res.stats.seeds_evaded_at == {1: 1}


def test_downgrade_also_stops():
    class Warn(FakeScorer):
        def __call__(self, items):
            return [
                v.model_copy(update={'action': 'warn', 'level': 'suspicious'})
                for v in super().__call__(items)
            ]

    fake = FakeOllama(_numbered)
    res = generate_g1(
        make_seeds()[1:],
        run_seed=1,
        round=1,
        client=fake.client(),
        scorer=Warn(),
    )
    assert res.stats.calls == 1
    assert res.stats.outcomes[1] == {'downgraded': 2}


def test_refusal_is_not_retried():
    fake = FakeOllama(lambda b, n: "I'm sorry, I can't help with that.")
    scorer = FakeScorer()
    res = generate_g1(
        make_seeds(),
        run_seed=1,
        round=1,
        client=fake.client(),
        scorer=scorer,
    )
    assert res.stats.calls == 2  # one per seed
    assert res.stats.refused == 2
    assert not res.variants and not scorer.calls


def test_invalid_output_is_retried():
    def reply(body, n):
        return '{"variants": [' if n == 0 else _numbered(body, n)

    fake = FakeOllama(reply)
    res = generate_g1(
        make_seeds()[1:],
        run_seed=1,
        round=1,
        client=fake.client(),
        scorer=FakeScorer(),
    )
    assert res.stats.calls == 3
    assert res.stats.invalid_output == 1
    # No variants from attempt 1, so attempt 2 has no feedback yet.
    assert 'reason IDs' not in fake.user_prompts()[1]
    assert 'reason IDs' in fake.user_prompts()[2]


def test_transport_error_counted():
    fake = FakeOllama(lambda b, n: httpx.Response(503))
    res = generate_g1(
        make_seeds()[1:],
        run_seed=1,
        round=1,
        client=fake.client(),
        scorer=FakeScorer(),
        attempts=2,
    )
    assert res.stats.calls == 2
    assert res.stats.errors == {'http-503': 2}
    assert res.stats.refused == 0 and res.stats.invalid_output == 0


def test_stable_ids_and_request_seeds():
    def run():
        fake = FakeOllama(_numbered)
        res = generate_g1(
            make_seeds(),
            run_seed=99,
            round=1,
            client=fake.client(),
            scorer=FakeScorer(),
        )
        return [v.id for v in res.variants], [r['seed'] for r in fake.requests]

    ids1, seeds1 = run()
    ids2, seeds2 = run()
    assert ids1 == ids2 and seeds1 == seeds2
    assert len(set(ids1)) == len(ids1) == 12
    assert all(re.fullmatch(r'g1[0-9a-f]{18}', i) for i in ids1)


def test_fallback_switch_after_pilot():
    def reply(body, n):
        if body['model'] == 'primary:1b':
            return 'I cannot help with that.'
        return vj(('sh', f'echo b{n}', 'quote'))

    seeds = [
        s.model_copy(update={'case_id': f'case.{i}'})
        for i in range(6)
        for s in make_seeds()[1:]
    ]
    fake = FakeOllama(reply)
    res = generate_g1(
        seeds,
        run_seed=1,
        round=1,
        client=fake.client(),
        scorer=FakeScorer(),
        attempts=1,
        fallback_models=('primary:1b', 'backup:1b'),
        pilot_calls=4,
    )
    models = [r['model'] for r in fake.requests]
    assert models == ['primary:1b'] * 4 + ['backup:1b'] * 2
    (switch,) = res.switches
    assert switch.from_model == REF
    assert switch.to_model == f'backup:1b@{DIGEST[:12]}'
    assert switch.refusal_rate == 1.0
    assert res.models == [REF, switch.to_model]
    assert all(v.model == switch.to_model for v in res.variants)
    assert res.stats.per_model[REF]['refused'] == 4


def test_no_switch_below_threshold():
    def reply(body, n):
        if n % 2:
            return 'I cannot help with that.'
        return vj(('sh', f'echo b{n}', 'quote'))

    seeds = [
        s.model_copy(update={'case_id': f'case.{i}'})
        for i in range(6)
        for s in make_seeds()[1:]
    ]
    fake = FakeOllama(reply)
    res = generate_g1(
        seeds,
        run_seed=1,
        round=1,
        client=fake.client(),
        scorer=FakeScorer(),
        attempts=1,
        fallback_models=('backup:1b',),
        pilot_calls=4,
    )
    assert not res.switches  # exactly 50% is not "over 50%"
    assert {r['model'] for r in fake.requests} == {'primary:1b'}


class FakeValidator:
    def __init__(self):
        self.calls = 0

    def validate(self, payload, shell):
        self.calls += 1
        if 'bad' in payload:
            return SyntaxVerdict(
                shell=shell,
                status='invalid',
                errors=(SyntaxIssue(id='sh.unexpected-eof', line=1),),
            )
        return SyntaxVerdict(shell=shell, status='ok')


def test_syntax_invalid_not_scored_and_fed_back():
    def reply(body, n):
        if n == 0:
            return vj(('sh', 'bad one', 'q'), ('sh', 'bad two', 'r'))
        return vj(('sh', f'echo {BYPASS}', 'q'))

    fake = FakeOllama(reply)
    scorer = FakeScorer(bypass_marker=BYPASS)
    res = generate_g1(
        make_seeds()[1:],
        run_seed=1,
        round=1,
        client=fake.client(),
        scorer=scorer,
        validator=FakeValidator(),
    )
    assert res.stats.calls == 2
    assert res.stats.syntax == {'invalid': 2, 'ok': 1}
    assert len(scorer.calls) == 1 and len(scorer.calls[0]) == 1
    second = fake.user_prompts()[1]
    assert 'sh.unexpected-eof' in second
    assert len(res.syntax) == 3
    assert res.stats.outcomes == {1: {}, 2: {'bypassed': 1}}


def test_audit_has_hashes_only(tmp_path: Path):
    payload_mark = J('MARK', 'ER_IN_RESPONSE_PAYLOAD')
    seed_mark = J('MARK', 'ER_IN_SEED')
    seeds = [
        s.model_copy(update={'payload': s.payload + ' #' + seed_mark})
        for s in make_seeds()
    ]

    def reply(body, n):
        return vj(('sh', f'echo {payload_mark} {n}', 'quote'))

    fake = FakeOllama(reply)
    audit = AuditLog(tmp_path / 'run-1' / 'audit.jsonl')
    res = generate_g1(
        seeds,
        run_seed=1,
        round=1,
        client=fake.client(),
        scorer=FakeScorer(),
        validator=FakeValidator(),
        audit=audit,
    )
    events = audit.events()
    assert {e.run_id for e in events} == {'run-1'}
    kinds = {(e.actor, e.event) for e in events}
    assert kinds == {
        ('red-g1', 'llm_call'),
        ('red-g1', 'generate'),
        ('validator', 'validate'),
        ('engine', 'detect'),
    }
    calls = [e for e in events if e.event == 'llm_call']
    assert len(calls) == res.stats.calls
    assert all(e.prompt_sha256 and e.response_sha256 for e in calls)
    assert all(e.params['seed'] and e.params['temperature'] for e in calls)
    assert all(e.model == REF for e in calls)
    gens = [e for e in events if e.event == 'generate']
    assert {e.payload_sha256 for e in gens} == {
        v.payload_sha256 for v in res.variants
    }
    known = [payload_mark, seed_mark]
    known += [
        p for r in fake.requests for m in r['messages'] for p in [m['content']]
    ]
    known += [v.payload for v in res.variants]
    known += [s.payload for s in seeds]
    assert find_leaks(audit.path, known) == []
    raw = audit.path.read_text()
    assert payload_mark not in raw and seed_mark not in raw
    assert 'example.invalid' not in raw


def test_stats_dict_has_no_text():
    mark = J('MARK', 'ER_STATS')
    fake = FakeOllama(_always(('sh', f'echo {mark}', 'quote')))
    res = generate_g1(
        make_seeds()[1:],
        run_seed=1,
        round=1,
        client=fake.client(),
        scorer=FakeScorer(),
        attempts=1,
    )
    assert mark not in repr(res.stats.as_dict())
    assert mark not in repr(res.variants)
    assert res.stats.mean_latency_ms >= 0
