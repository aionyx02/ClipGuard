"""Append-only audit log (phase-5.md §5.8).

``redteam/runs/<run-id>/audit.jsonl`` holds one ``AuditEvent`` per line:
hashes and IDs only. ``find_leaks`` is the check that no event carries a
payload (or any other known secret text) in any field.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime
from pathlib import Path

from redteam.models import AuditEvent

# Shorter known texts are not checked: a 3-character payload would match
# hex digests by chance.
MIN_LEAK_CHARS = 8


def now_ts() -> str:
    return datetime.now(UTC).isoformat(timespec='milliseconds')


class AuditLog:
    """Writer for one run's ``audit.jsonl``. Opens in append mode only."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def append(self, event: AuditEvent) -> None:
        self.extend([event])

    def extend(self, events: Iterable[AuditEvent]) -> int:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        n = 0
        with self.path.open('a', encoding='utf-8') as fh:
            for event in events:
                fh.write(event.model_dump_json() + '\n')
                n += 1
            fh.flush()
        return n

    def events(self) -> list[AuditEvent]:
        return list(read_events(self.path))


def read_events(path: Path) -> Iterator[AuditEvent]:
    if not path.exists():
        return
    with path.open(encoding='utf-8') as fh:
        for line in fh:
            if line.strip():
                yield AuditEvent.model_validate_json(line)


def _strings(value: object) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield str(k)
            yield from _strings(v)
    elif isinstance(value, list | tuple):
        for v in value:
            yield from _strings(v)


def find_leaks(path: Path, known: Iterable[str]) -> list[tuple[int, str]]:
    """(line number, field path) of every event field containing a known
    text. Both the raw JSON line and the decoded values are checked, so an
    escaped payload (``\\u200b``, ``\\"``) is caught too. The text itself is
    never returned."""
    texts = [t for t in set(known) if len(t) >= MIN_LEAK_CHARS]
    hits: list[tuple[int, str]] = []
    if not path.exists() or not texts:
        return hits
    with path.open(encoding='utf-8') as fh:
        for n, line in enumerate(fh, 1):
            if not line.strip():
                continue
            record = json.loads(line)
            for key, value in record.items():
                for s in _strings(value):
                    if any(t in s for t in texts):
                        hits.append((n, key))
                        break
            if not any(h[0] == n for h in hits) and any(
                json.dumps(t)[1:-1] in line for t in texts
            ):
                hits.append((n, '<raw>'))
    return hits


def summarize(events: Iterable[AuditEvent]) -> list[dict[str, object]]:
    """Per-round counts for ``audit-summary.jsonl`` (committed with the
    report): events per actor/event, outcomes, models and rules revisions."""
    rounds: dict[int, dict[str, object]] = {}
    for e in events:
        r = rounds.setdefault(
            e.round,
            {
                'round': e.round,
                'events': Counter(),
                'results': Counter(),
                'models': set(),
                'rules_revs': set(),
                'duration_ms': 0,
                'tokens_in': 0,
                'tokens_out': 0,
            },
        )
        r['events'][f'{e.actor}:{e.event}'] += 1
        action = e.result.get('action')
        if isinstance(action, str):
            r['results'][f'action:{action}'] += 1
        syntax = e.result.get('syntax_ok')
        if isinstance(syntax, bool):
            r['results'][f'syntax_ok:{str(syntax).lower()}'] += 1
        if e.model:
            r['models'].add(e.model)
        if e.rules_rev:
            r['rules_revs'].add(e.rules_rev)
        r['duration_ms'] += e.duration_ms or 0
        r['tokens_in'] += e.tokens.get('in', 0)
        r['tokens_out'] += e.tokens.get('out', 0)
    out = []
    for n in sorted(rounds):
        r = rounds[n]
        out.append(
            {
                **r,
                'events': dict(sorted(r['events'].items())),
                'results': dict(sorted(r['results'].items())),
                'models': sorted(r['models']),
                'rules_revs': sorted(r['rules_revs']),
            }
        )
    return out


def write_summary(events: Iterable[AuditEvent], path: Path) -> int:
    rows = summarize(events)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        ''.join(json.dumps(r, ensure_ascii=False) + '\n' for r in rows),
        encoding='utf-8',
    )
    return len(rows)
