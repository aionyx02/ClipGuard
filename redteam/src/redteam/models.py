"""Shared data models for the red/blue loop (docs/plan/phase-5.md).

Every module and every parallel workstream uses these types, so change them
only in the main session.

Payload rule (§5.3.4): a payload lives in memory only. ``payload`` fields are
excluded from ``repr`` and from every ``model_dump`` / ``model_dump_json``, so
an accidental log line or JSON dump never contains it. ``redteam.store`` is the
only code that persists payloads, and it writes them as ``parts``.
"""

from __future__ import annotations

import hashlib
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, computed_field


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


class Shell(StrEnum):
    CMD = 'cmd'
    POWERSHELL = 'powershell'
    SH = 'sh'
    BASH = 'bash'
    ZSH = 'zsh'
    APPLESCRIPT = 'applescript'


Split = Literal['train', 'heldout']
Generator = Literal['g0', 'g1']
Action = Literal['allow', 'warn', 'quarantine']
Level = Literal['none', 'suspicious', 'malicious']


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra='forbid')


class Seed(_Model):
    """A malicious corpus command case, assembled from its ``parts``."""

    case_id: str
    shell: Shell
    split: Split
    payload: str = Field(repr=False, exclude=True)

    @computed_field
    @property
    def payload_sha256(self) -> str:
        return sha256_hex(self.payload)


class Variant(_Model):
    """One generated variant of a seed (or of another variant)."""

    id: str
    seed_id: str
    parent_id: str | None = None
    round: int
    generator: Generator
    techniques: tuple[str, ...]
    shell: Shell
    # G1 only: 'qwen3.8:27b-mlx@<digest>' or the fallback model actually used.
    model: str | None = None
    payload: str = Field(repr=False, exclude=True)

    @computed_field
    @property
    def payload_sha256(self) -> str:
        return sha256_hex(self.payload)


SyntaxStatus = Literal[
    'ok',
    'invalid',
    # Refused before parsing (`using module` / `using assembly`, S8 §1).
    'rejected_unsafe',
    # Timeout, crash or protocol error: never counts as valid (S8 §5).
    'validator_crash',
    # No validator for this shell on this machine.
    'unchecked',
]


class SyntaxIssue(_Model):
    """A parser error: an ID and a position, never the payload text."""

    id: str
    line: int | None = None
    column: int | None = None


class SyntaxVerdict(_Model):
    shell: Shell
    status: SyntaxStatus
    errors: tuple[SyntaxIssue, ...] = ()
    # Recursively validated inner scripts (-EncodedCommand, -c, bash -c,
    # eval), at most 5 levels deep.
    inner: tuple[SyntaxVerdict, ...] = ()

    @property
    def ok(self) -> bool:
        return self.status == 'ok' and all(i.ok for i in self.inner)


Outcome = Literal['blocked', 'downgraded', 'bypassed']


class EngineVerdict(_Model):
    variant_id: str
    rules_rev: str
    action: Action
    level: Level
    risk_score: int
    reason_ids: tuple[str, ...]
    duration_us: int

    @property
    def outcome(self) -> Outcome:
        # §5.4: quarantine is a block, warn a downgrade, allow a bypass.
        return {
            'quarantine': 'blocked',
            'warn': 'downgraded',
            'allow': 'bypassed',
        }[self.action]


Actor = Literal[
    'red-g0', 'red-g1', 'validator', 'engine', 'blue', 'orchestrator'
]


class AuditEvent(_Model):
    """One line of ``audit.jsonl`` (§5.8). Hashes only, never raw text."""

    ts: str
    run_id: str
    round: int
    actor: Actor
    event: str
    variant_id: str | None = None
    payload_sha256: str | None = None
    rules_rev: str | None = None
    model: str | None = None
    params: dict[str, float | int | str | bool] = Field(default_factory=dict)
    prompt_sha256: str | None = None
    response_sha256: str | None = None
    result: dict[str, object] = Field(default_factory=dict)
    duration_ms: int | None = None
    tokens: dict[str, int] = Field(default_factory=dict)
