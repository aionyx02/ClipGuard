"""Run store and frozen eval files (phase-5.md §5.3.4).

This is the only module that persists payloads, and it writes them only as
corpus-style ``parts`` of ``STORE_PART_CHARS`` characters, so no file holds a
whole command keyword (Defender) or a whole key (push protection).

Layout of ``redteam/runs/<run-id>/`` (gitignored):

- ``variants.jsonl``: one ``Variant.model_dump()`` + ``parts`` per line. This is
  what ``cargo run -p xtask -- corpus add-from-run`` reads.
- ``seeds.jsonl``: the seeds of the run, same encoding.
- ``syntax.jsonl`` / ``verdicts.jsonl``: payload-free verdicts.
- ``audit.jsonl``: see ``redteam.audit``.

Frozen files in ``redteam/eval/`` (committed) use the same records plus a
``type`` field (``seed`` | ``variant`` | ``benign``).
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel

from redteam.models import (
    EngineVerdict,
    Seed,
    SyntaxVerdict,
    Variant,
    sha256_hex,
)

STORE_PART_CHARS = 6

REDTEAM_DIR = Path(__file__).resolve().parents[2]
RUNS_DIR = REDTEAM_DIR / 'runs'
EVAL_DIR = REDTEAM_DIR / 'eval'

VARIANTS_FILE = 'variants.jsonl'
SEEDS_FILE = 'seeds.jsonl'
SYNTAX_FILE = 'syntax.jsonl'
VERDICTS_FILE = 'verdicts.jsonl'
AUDIT_FILE = 'audit.jsonl'

_RUN_ID = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')


class StoreError(ValueError):
    """A store record that is malformed or fails its hash check."""


def to_parts(text: str, size: int = STORE_PART_CHARS) -> list[str]:
    """Split by code point (never inside a surrogate pair once encoded)."""
    if size < 1:
        raise ValueError('size must be positive')
    return [text[i : i + size] for i in range(0, len(text), size)]


def from_parts(parts: object) -> str:
    if not isinstance(parts, list) or not all(
        isinstance(p, str) for p in parts
    ):
        raise StoreError('`parts` must be a list of strings')
    return ''.join(parts)


def _dumps(record: dict[str, Any]) -> str:
    # ensure_ascii keeps invisible characters as \\uXXXX escapes.
    return json.dumps(record, ensure_ascii=True, separators=(',', ':'))


def encode(model: Seed | Variant, **extra: Any) -> dict[str, Any]:
    record = model.model_dump(mode='json')
    record.update(extra)
    record['parts'] = to_parts(model.payload)
    return record


def _checked_payload(record: dict[str, Any]) -> str:
    payload = from_parts(record.pop('parts', None))
    expected = record.pop('payload_sha256', None)
    if expected is not None and expected != sha256_hex(payload):
        raise StoreError('payload_sha256 does not match parts')
    return payload


def decode_variant(record: dict[str, Any]) -> Variant:
    record = dict(record)
    record.pop('type', None)
    payload = _checked_payload(record)
    return Variant(**record, payload=payload)


def decode_seed(record: dict[str, Any]) -> Seed:
    record = dict(record)
    record.pop('type', None)
    payload = _checked_payload(record)
    return Seed(**record, payload=payload)


def _read_jsonl(path: Path) -> Iterator[dict[str, Any]]:
    if not path.exists():
        return
    with path.open(encoding='utf-8') as fh:
        for n, line in enumerate(fh, 1):
            if line.strip():
                try:
                    yield json.loads(line)
                except json.JSONDecodeError as e:
                    raise StoreError(f'{path.name}:{n}: invalid JSON') from e


def _append_jsonl(path: Path, records: Iterable[str]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with path.open('a', encoding='utf-8') as fh:
        for line in records:
            fh.write(line + '\n')
            n += 1
    return n


class RunStore:
    """``redteam/runs/<run-id>/``."""

    def __init__(self, run_id: str, root: Path = RUNS_DIR) -> None:
        if not _RUN_ID.match(run_id):
            raise ValueError(f'invalid run id {run_id!r}')
        self.run_id = run_id
        self.dir = root / run_id

    def create(self) -> RunStore:
        self.dir.mkdir(parents=True, exist_ok=True)
        return self

    @property
    def audit_path(self) -> Path:
        return self.dir / AUDIT_FILE

    # -- payload records --------------------------------------------------

    def add_variants(self, variants: Iterable[Variant]) -> int:
        return _append_jsonl(
            self.dir / VARIANTS_FILE, (_dumps(encode(v)) for v in variants)
        )

    def variants(self) -> list[Variant]:
        return [
            decode_variant(r) for r in _read_jsonl(self.dir / VARIANTS_FILE)
        ]

    def variant(self, variant_id: str) -> Variant | None:
        for record in _read_jsonl(self.dir / VARIANTS_FILE):
            if record.get('id') == variant_id:
                return decode_variant(record)
        return None

    def add_seeds(self, seeds: Iterable[Seed]) -> int:
        return _append_jsonl(
            self.dir / SEEDS_FILE, (_dumps(encode(s)) for s in seeds)
        )

    def seeds(self) -> list[Seed]:
        return [decode_seed(r) for r in _read_jsonl(self.dir / SEEDS_FILE)]

    # -- payload-free records ---------------------------------------------

    def add_syntax(self, items: Iterable[tuple[str, SyntaxVerdict]]) -> int:
        return _append_jsonl(
            self.dir / SYNTAX_FILE,
            (
                _dumps({'variant_id': vid, **v.model_dump(mode='json')})
                for vid, v in items
            ),
        )

    def syntax(self) -> dict[str, SyntaxVerdict]:
        out = {}
        for r in _read_jsonl(self.dir / SYNTAX_FILE):
            vid = r.pop('variant_id')
            out[vid] = SyntaxVerdict.model_validate(r)
        return out

    def add_verdicts(self, verdicts: Iterable[EngineVerdict]) -> int:
        return _append_jsonl(
            self.dir / VERDICTS_FILE,
            (_dumps(v.model_dump(mode='json')) for v in verdicts),
        )

    def verdicts(self) -> list[EngineVerdict]:
        return [
            EngineVerdict.model_validate(r)
            for r in _read_jsonl(self.dir / VERDICTS_FILE)
        ]


# --- frozen eval files (redteam/eval/*.jsonl) -------------------------------

EvalType = Literal['seed', 'variant', 'benign']


class BenignItem(BaseModel):
    """A benign sample for the false-positive metric (§5.4)."""

    id: str
    tags: tuple[str, ...] = ()
    text: str

    def __repr__(self) -> str:  # never show the text
        return f'BenignItem(id={self.id!r})'

    __str__ = __repr__


EvalItem = Seed | Variant | BenignItem


def write_eval(path: Path, items: Iterable[EvalItem]) -> int:
    """Write a frozen eval file (overwrites: regenerated, not appended)."""
    lines = []
    for item in items:
        if isinstance(item, Seed):
            lines.append(_dumps(encode(item, type='seed')))
        elif isinstance(item, Variant):
            lines.append(_dumps(encode(item, type='variant')))
        else:
            lines.append(
                _dumps(
                    {
                        'type': 'benign',
                        'id': item.id,
                        'tags': list(item.tags),
                        'parts': to_parts(item.text),
                    }
                )
            )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(''.join(line + '\n' for line in lines), encoding='utf-8')
    return len(lines)


def read_eval(path: Path) -> list[EvalItem]:
    """Read a frozen eval file.

    Besides store records, benign files may use the corpus case format
    (``{"id", "input": Text, ...}``), so a hand-written ``benign-extra.jsonl``
    can follow ``corpus/benign``.
    """
    from redteam.seeds import resolve_text

    out: list[EvalItem] = []
    for record in _read_jsonl(path):
        kind = record.get('type')
        if kind == 'seed':
            out.append(decode_seed(record))
        elif kind == 'variant':
            out.append(decode_variant(record))
        elif kind == 'benign':
            out.append(
                BenignItem(
                    id=record['id'],
                    tags=tuple(record.get('tags', ())),
                    text=from_parts(record['parts']),
                )
            )
        elif 'input' in record:
            out.append(
                BenignItem(
                    id=record['id'],
                    tags=tuple(record.get('tags', ())),
                    text=resolve_text(record['input']),
                )
            )
        else:
            raise StoreError(f'{path.name}: unknown record type {kind!r}')
    return out
