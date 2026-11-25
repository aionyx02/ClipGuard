import json

from redteam.audit import (
    AuditLog,
    find_leaks,
    now_ts,
    read_events,
    summarize,
    write_summary,
)
from redteam.models import AuditEvent, sha256_hex

MARKER = 'PW-MARKER-PAYLOAD-​-7f3a'


def event(**kw):
    base = {
        'ts': now_ts(),
        'run_id': 'run-1',
        'round': 1,
        'actor': 'engine',
        'event': 'detect',
        'variant_id': 'g0aaa',
        'payload_sha256': sha256_hex(MARKER),
        'rules_rev': 'abc123',
        'result': {'action': 'warn', 'reason_ids': ['cmd-x']},
        'duration_ms': 3,
    }
    base.update(kw)
    return AuditEvent(**base)


def test_append_only(tmp_path):
    log = AuditLog(tmp_path / 'audit.jsonl')
    log.append(event())
    log.extend([event(actor='validator', event='validate')])
    AuditLog(tmp_path / 'audit.jsonl').append(event(round=2))
    events = list(read_events(tmp_path / 'audit.jsonl'))
    assert [e.round for e in events] == [1, 1, 2]
    assert events[0] == event(ts=events[0].ts)


def test_clean_log_has_no_leaks(tmp_path):
    log = AuditLog(tmp_path / 'audit.jsonl')
    log.extend([event(), event(model='qwen', params={'seed': 1})])
    assert find_leaks(log.path, [MARKER]) == []


def test_leaks_are_found_in_any_field(tmp_path):
    log = AuditLog(tmp_path / 'audit.jsonl')
    log.extend(
        [
            event(),
            event(result={'note': f'x {MARKER} y'}),
            event(model=MARKER),
            event(params={'p': MARKER}),
        ]
    )
    hits = find_leaks(log.path, [MARKER, 'abc'])
    assert hits == [(2, 'result'), (3, 'model'), (4, 'params')]
    # The report of a leak never contains the text itself.
    assert MARKER not in repr(hits)


def test_escaped_leak_in_raw_line(tmp_path):
    path = tmp_path / 'audit.jsonl'
    line = json.loads(event().model_dump_json())
    line['extra_blob'] = 'zz' + MARKER
    path.write_text(json.dumps(line) + '\n')
    assert find_leaks(path, [MARKER]) == [(1, 'extra_blob')]


def test_summary(tmp_path):
    events = [
        event(),
        event(result={'action': 'quarantine'}),
        event(actor='validator', event='validate', result={'syntax_ok': True}),
        event(round=2, model='m@1', tokens={'in': 5, 'out': 7}),
    ]
    rows = summarize(events)
    assert [r['round'] for r in rows] == [1, 2]
    assert rows[0]['events'] == {'engine:detect': 2, 'validator:validate': 1}
    assert rows[0]['results'] == {
        'action:quarantine': 1,
        'action:warn': 1,
        'syntax_ok:true': 1,
    }
    assert rows[1]['models'] == ['m@1'] and rows[1]['tokens_out'] == 7
    out = tmp_path / 'audit-summary.jsonl'
    assert write_summary(events, out) == 2
    assert len(out.read_text().splitlines()) == 2
