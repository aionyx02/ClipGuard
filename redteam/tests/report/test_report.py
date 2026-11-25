import json
import xml.etree.ElementTree as ET

import pytest

from redteam.models import EngineVerdict, Seed, Shell, SyntaxVerdict, Variant
from redteam.report import (
    GenerationStats,
    PatchCost,
    Report,
    RoundInput,
    ScoredItem,
    VersionInput,
    build_report,
    join,
    write_report,
)
from redteam.report.render import CHARTS, render_markdown

MARKER = 'PW-MARKER-PAYLOAD-0001'


def item(i, split, action, gen='g0', rnd=1, techs=('ps.concat',), **kw):
    return ScoredItem(
        variant_id=f'v{i}',
        seed_id=f's{i % 5}',
        split=split,
        round=rnd,
        generator=gen,
        techniques=techs,
        shell=Shell.POWERSHELL,
        action=action,
        level={'quarantine': 'malicious', 'warn': 'suspicious'}.get(
            action, 'none'
        ),
        risk_score=50,
        duration_us=i * 10,
        **kw,
    )


def versions():
    v1 = [item(i, 'heldout', 'quarantine') for i in range(6)]
    v1 += [item(i, 'heldout', 'warn') for i in range(6, 8)]
    v1 += [item(i, 'heldout', 'allow') for i in range(8, 10)]
    v1 += [
        item(i, 'train', 'quarantine', techs=('cmd.caret',))
        for i in range(10, 15)
    ]
    v1 += [
        item(15, 'heldout', 'allow', syntax_status='invalid'),
        item(16, 'heldout', 'allow', syntax_status='unchecked'),
        item(17, 'heldout', 'quarantine', techs=('common.zero_width',)),
    ]
    v2 = [i.model_copy(update={'action': 'quarantine'}) for i in v1[:9]]
    return [
        VersionInput(
            label='V1',
            rules_rev='a' * 40,
            items=tuple(v1),
            benign_corpus=('allow',) * 95 + ('warn',) * 4 + ('quarantine',),
            benign_extra=('allow',) * 9 + ('warn',),
        ),
        VersionInput(
            label='V2',
            rules_rev='b' * 40,
            items=tuple(v2),
            benign_corpus=('allow',) * 98 + ('warn',) * 2,
        ),
    ]


def rounds():
    r1 = [
        item(100 + i, 'train', 'allow' if i < 3 else 'quarantine')
        for i in range(10)
    ]
    r1 += [
        item(200, 'train', 'warn', gen='g1', equivalence='equivalent'),
        item(201, 'train', 'allow', gen='g1'),
        item(202, 'train', 'quarantine', gen='g1'),
        item(203, 'heldout', 'allow', gen='g1'),
    ]
    r2 = [
        item(300 + i, 'train', 'allow' if i < 1 else 'quarantine', rnd=2)
        for i in range(10)
    ]
    return [
        RoundInput(round=1, version='V1', items=tuple(r1)),
        RoundInput(round=2, version='V2', items=tuple(r2)),
    ]


def report() -> Report:
    return build_report(
        versions(),
        rounds(),
        patch_costs=[
            PatchCost(
                round=1,
                pr='#50',
                rules_lines_changed=12,
                corpus_cases_added=4,
                heldout_p99_us=420,
                blue_minutes=31.5,
                blue_turns=88,
                model='m',
            ),
            PatchCost(round=2, heldout_p99_us=1500),
        ],
        generation=[
            GenerationStats(
                round=1,
                generator='g1',
                model='qwen',
                requested=30,
                produced=20,
                refused=6,
                invalid_output=4,
            )
        ],
        generated_at='2026-11-25T00:00:00+00:00',
        notes=['fixture'],
    )


def test_metric_1_detection():
    r = report()
    d = {(x.version, x.split): x for x in r.detection}
    v1h = d[('V1', 'heldout')]
    # 10 normal + unchecked + zero-width probe; the invalid one is excluded.
    assert (v1h.valid, v1h.blocked, v1h.downgraded, v1h.bypassed) == (
        12,
        7,
        2,
        3,
    )
    assert v1h.detection_rate == round(7 / 12, 4)
    assert v1h.at_least_warn_rate == 0.75
    assert d[('V1', 'train')].detection_rate == 1.0
    assert d[('V2', 'heldout')].detection_rate == 1.0
    assert (
        d[('V2', 'train')].valid == 0
        and d[('V2', 'train')].detection_rate is None
    )


def test_unchecked_can_be_excluded():
    r = build_report(versions(), count_unchecked_as_valid=False)
    v1h = next(
        x for x in r.detection if x.version == 'V1' and x.split == 'heldout'
    )
    assert v1h.valid == 11


def test_metric_2_false_positives():
    fp = {(x.version, x.dataset): x for x in report().false_positives}
    assert fp[('V1', 'corpus')].fp_rate == 0.05
    assert fp[('V1', 'corpus')].warn == 4
    assert fp[('V1', 'corpus')].quarantine_rate == 0.01
    assert fp[('V1', 'extra')].warn_rate == 0.1
    assert fp[('V1', 'all')].n == 110
    assert ('V2', 'extra') not in fp
    assert fp[('V2', 'all')].fp_rate == 0.02


def test_metric_3_attack_success():
    a = {(x.round, x.generator): x for x in report().attack_success}
    assert a[(1, 'g0')].success_rate == 0.3
    assert a[(1, 'g0')].allowed == 3
    g1 = a[(1, 'g1')]
    # The heldout G1 item does not count (train only).
    assert (g1.valid, g1.not_blocked, g1.allowed) == (3, 2, 1)
    assert (g1.confirmed_equivalent, g1.unconfirmed) == (1, 1)
    assert a[(2, 'g0')].success_rate == 0.1
    assert (2, 'g1') not in a


def test_metric_4_patch_cost_and_aux():
    r = report()
    assert [p.within_budget for p in r.patch_cost] == [True, False]
    g = r.generation[0]
    assert g.refusal_rate == 0.2 and g.invalid_output_rate == round(4 / 30, 4)
    t = {(x.version, x.technique): x for x in r.techniques}
    assert t[('V1', 'cmd.caret')].detection_rate == 1.0
    assert t[('V1', 'common.zero_width')].semantic is False
    assert t[('V1', 'ps.concat')].semantic is True
    val = {v.generator: v for v in r.validity}
    assert val['g0'].statuses['invalid'] == 1
    assert val['g1'].total == 4
    lat = {x.version: x for x in r.latency}
    assert lat['V1'].p99_us == 170 and lat['V1'].max_us == 170


def test_join_from_models():
    seed = Seed(
        case_id='command.a', shell=Shell.CMD, split='train', payload=MARKER
    )
    var = Variant(
        id='g0x',
        seed_id='command.a',
        round=1,
        generator='g0',
        techniques=('common.homoglyph',),
        shell=Shell.CMD,
        payload=MARKER + '!',
    )
    verdicts = [
        EngineVerdict(
            variant_id=i,
            rules_rev='r',
            action=a,
            level='none',
            risk_score=0,
            reason_ids=('r1',),
            duration_us=5,
        )
        for i, a in (('command.a', 'quarantine'), ('g0x', 'allow'))
    ]
    syntax = {
        'g0x': SyntaxVerdict(
            shell=Shell.CMD,
            status='ok',
            inner=(SyntaxVerdict(shell=Shell.CMD, status='invalid'),),
        )
    }
    items = join(
        [seed, var], verdicts, splits={'command.a': 'heldout'}, syntax=syntax
    )
    assert [i.variant_id for i in items] == ['command.a', 'g0x']
    assert items[0].generator is None and items[0].split == 'heldout'
    assert items[1].syntax_status == 'invalid'
    assert items[1].semantic is False
    assert MARKER not in json.dumps([i.model_dump() for i in items])


def test_write_report(tmp_path):
    r = report()
    paths = write_report(r, tmp_path)
    names = {p.name for p in paths}
    assert {'report.json', 'report.md'} <= names
    for chart in CHARTS:
        for suffix in ('', '-dark'):
            svg = tmp_path / f'{chart}{suffix}.svg'
            assert svg.name in names
            ET.parse(svg)  # noqa: S314 (our own output)
    loaded = Report.model_validate_json((tmp_path / 'report.json').read_text())
    assert loaded == r
    md = (tmp_path / 'report.md').read_text()
    assert '| V1 | heldout | 12 | 7 | 2 | 3 | 58.3% | 75.0% |' in md
    assert '| `ps.concat` | 9 | 100.0% | 100.0% |' in md
    light = (tmp_path / 'detection-fp.svg').read_text()
    dark = (tmp_path / 'detection-fp-dark.svg').read_text()
    assert '#191919' in light and '#efefef' in dark
    assert light != dark


def test_empty_inputs_render():
    r = build_report([VersionInput(label='V1', rules_rev='x')])
    assert render_markdown(r)


@pytest.mark.parametrize('field', ['payload', 'parts', 'text'])
def test_report_schema_has_no_payload_fields(field):
    schema = json.dumps(Report.model_json_schema())
    assert f'"{field}"' not in schema
