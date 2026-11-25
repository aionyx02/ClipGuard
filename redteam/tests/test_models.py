from redteam.models import EngineVerdict, Seed, Shell, SyntaxVerdict, Variant

MARK = 'PW-PAYLOAD-MARKER'


def _variant() -> Variant:
    return Variant(
        id='v1',
        seed_id='s1',
        round=1,
        generator='g0',
        techniques=('caret',),
        shell=Shell.CMD,
        payload=f'echo {MARK}',
    )


def test_payload_never_serialized_or_printed():
    seed = Seed(
        case_id='c', shell=Shell.CMD, split='train', payload=f'echo {MARK}'
    )
    for model in (seed, _variant()):
        assert MARK not in repr(model)
        assert MARK not in str(model)
        assert MARK not in model.model_dump_json()
        assert 'payload' not in model.model_dump()
        assert len(model.payload_sha256) == 64


def test_inner_failure_fails_outer():
    inner = SyntaxVerdict(shell=Shell.POWERSHELL, status='invalid')
    outer = SyntaxVerdict(shell=Shell.CMD, status='ok', inner=(inner,))
    assert not outer.ok
    assert SyntaxVerdict(shell=Shell.SH, status='ok').ok
    assert not SyntaxVerdict(shell=Shell.SH, status='validator_crash').ok


def test_outcome_mapping():
    def verdict(action):
        return EngineVerdict(
            variant_id='v',
            rules_rev='r',
            action=action,
            level='none',
            risk_score=0,
            reason_ids=(),
            duration_us=1,
        )

    assert verdict('quarantine').outcome == 'blocked'
    assert verdict('warn').outcome == 'downgraded'
    assert verdict('allow').outcome == 'bypassed'
