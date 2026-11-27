import json

import pytest

from redteam.models import (
    EngineVerdict,
    Seed,
    Shell,
    SyntaxIssue,
    SyntaxVerdict,
    Variant,
)
from redteam.mutate import _kw
from redteam.store import (
    STORE_PART_CHARS,
    BenignItem,
    RunStore,
    StoreError,
    from_parts,
    read_eval,
    to_parts,
    write_eval,
)

PAYLOAD = f'{_kw.PS} -w hidden -c "{_kw.IEX} x" ​\U000e0041 é'


def variant(payload=PAYLOAD, vid='g0aaa'):
    return Variant(
        id=vid,
        seed_id='command.t.1',
        round=1,
        generator='g0',
        techniques=('ps.concat', 'common.padding'),
        shell=Shell.POWERSHELL,
        payload=payload,
    )


def test_parts_round_trip_and_size():
    parts = to_parts(PAYLOAD)
    assert all(len(p) <= STORE_PART_CHARS for p in parts)
    assert from_parts(parts) == PAYLOAD
    assert to_parts('') == []
    assert _kw.PS not in parts


def test_run_store_round_trip(tmp_path):
    store = RunStore('run-1', root=tmp_path).create()
    assert store.add_variants([variant(), variant('abc', 'g0bbb')]) == 2
    loaded = store.variants()
    assert [v.id for v in loaded] == ['g0aaa', 'g0bbb']
    assert loaded[0].payload == PAYLOAD
    assert loaded[0] == variant()
    assert store.variant('g0bbb').payload == 'abc'
    assert store.variant('nope') is None

    raw = (store.dir / 'variants.jsonl').read_text(encoding='utf-8')
    assert raw.isascii()
    assert f'{_kw.PS} -w' not in raw
    first = json.loads(raw.splitlines()[0])
    assert first['payload_sha256'] == variant().payload_sha256
    assert 'payload' not in first


def test_tampered_parts_are_rejected(tmp_path):
    store = RunStore('run-1', root=tmp_path).create()
    store.add_variants([variant()])
    path = store.dir / 'variants.jsonl'
    rec = json.loads(path.read_text())
    rec['parts'][0] = 'xxxxxx'
    path.write_text(json.dumps(rec) + '\n')
    with pytest.raises(StoreError):
        store.variants()


def test_seeds_syntax_and_verdicts(tmp_path):
    store = RunStore('r2', root=tmp_path).create()
    seed = Seed(
        case_id='command.t.1', shell=Shell.CMD, split='train', payload='ab'
    )
    store.add_seeds([seed])
    assert store.seeds() == [seed]
    sv = SyntaxVerdict(
        shell=Shell.CMD,
        status='invalid',
        errors=(SyntaxIssue(id='E1', line=1, column=2),),
    )
    store.add_syntax([('g0aaa', sv)])
    assert store.syntax() == {'g0aaa': sv}
    ev = EngineVerdict(
        variant_id='g0aaa',
        rules_rev='abc',
        action='warn',
        level='suspicious',
        risk_score=40,
        reason_ids=('cmd-x',),
        duration_us=12,
    )
    store.add_verdicts([ev])
    assert store.verdicts() == [ev]


def test_invalid_run_id():
    with pytest.raises(ValueError):
        RunStore('../escape')


def test_eval_file_round_trip(tmp_path):
    seed = Seed(
        case_id='command.t.1',
        shell=Shell.POWERSHELL,
        split='heldout',
        payload=PAYLOAD,
    )
    benign = BenignItem(id='benign.x', tags=('git',), text='git status')
    path = tmp_path / 'heldout.jsonl'
    assert write_eval(path, [seed, variant(), benign]) == 3
    raw = path.read_text()
    assert f'{_kw.PS} -w' not in raw
    items = read_eval(path)
    assert items[0] == seed
    assert items[1] == variant()
    assert items[2] == benign
    assert 'git status' not in repr(items[2])


def test_eval_reads_corpus_style_benign(tmp_path):
    path = tmp_path / 'benign-extra.jsonl'
    path.write_text(
        json.dumps({'id': 'b.1', 'input': {'parts': ['git ', 'log']}}) + '\n'
    )
    [item] = read_eval(path)
    assert item.text == 'git log'
