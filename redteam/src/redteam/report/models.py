"""Report data (``report.json``, phase-5.md §5.4). Payload-free by design."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, computed_field

from redteam.models import Action, Generator, Level, Shell, Split, SyntaxStatus


class _M(BaseModel):
    # 'ignore': report.json carries computed rates, which load back as
    # recomputed fields.
    model_config = ConfigDict(frozen=True, extra='ignore')


def _rate(k: int, n: int) -> float | None:
    return round(k / n, 4) if n else None


class ScoredItem(_M):
    """One malicious payload (seed or variant) joined with its verdicts."""

    variant_id: str
    seed_id: str
    split: Split
    round: int
    generator: Generator | None  # None for a seed itself
    techniques: tuple[str, ...] = ()
    shell: Shell
    # False when a technique in the chain is a normalization probe.
    semantic: bool = True
    syntax_status: SyntaxStatus | None = None
    # G1 only: the blue team's equivalence judgement (§5.3.5).
    equivalence: str | None = None
    action: Action
    level: Level
    risk_score: int
    reason_ids: tuple[str, ...] = ()
    duration_us: int = 0


class VersionInput(_M):
    """Evaluation of one engine version (V1, V2, V3)."""

    label: str
    rules_rev: str
    items: tuple[ScoredItem, ...] = ()
    benign_corpus: tuple[Action, ...] = ()
    benign_extra: tuple[Action, ...] = ()


class RoundInput(_M):
    """New variants the red team made in one round, against ``version``."""

    round: int
    version: str
    items: tuple[ScoredItem, ...] = ()


class GenerationStats(_M):
    round: int
    generator: Generator
    model: str | None = None
    requested: int = 0
    produced: int = 0
    refused: int = 0
    invalid_output: int = 0

    @computed_field
    @property
    def refusal_rate(self) -> float | None:
        return _rate(self.refused, self.requested)

    @computed_field
    @property
    def invalid_output_rate(self) -> float | None:
        return _rate(self.invalid_output, self.requested)


class PatchCost(_M):
    """Metric 4, from the blue-team PR of a round (given by the caller)."""

    round: int
    pr: str | None = None
    rules_lines_changed: int = 0
    corpus_cases_added: int = 0
    heldout_p99_us: int | None = None
    blue_minutes: float | None = None
    blue_turns: int | None = None
    model: str | None = None
    # phase-1.md performance budget: 1 KB input <= 1 ms.
    budget_us: int = 1000

    @computed_field
    @property
    def within_budget(self) -> bool | None:
        if self.heldout_p99_us is None:
            return None
        return self.heldout_p99_us <= self.budget_us


class Detection(_M):
    """Metric 1."""

    version: str
    split: Split
    valid: int
    blocked: int
    downgraded: int
    bypassed: int

    @computed_field
    @property
    def detection_rate(self) -> float | None:
        return _rate(self.blocked, self.valid)

    @computed_field
    @property
    def at_least_warn_rate(self) -> float | None:
        return _rate(self.blocked + self.downgraded, self.valid)


class FalsePositives(_M):
    """Metric 2."""

    version: str
    dataset: str  # corpus | extra | all
    n: int
    warn: int
    quarantine: int

    @computed_field
    @property
    def fp_rate(self) -> float | None:
        return _rate(self.warn + self.quarantine, self.n)

    @computed_field
    @property
    def warn_rate(self) -> float | None:
        return _rate(self.warn, self.n)

    @computed_field
    @property
    def quarantine_rate(self) -> float | None:
        return _rate(self.quarantine, self.n)


class AttackSuccess(_M):
    """Metric 3: share of a round's new valid train variants not blocked."""

    round: int
    version: str
    generator: Generator
    valid: int
    not_blocked: int
    allowed: int
    # G1 bypasses split by the blue team's equivalence judgement.
    confirmed_equivalent: int = 0
    unconfirmed: int = 0

    @computed_field
    @property
    def success_rate(self) -> float | None:
        return _rate(self.not_blocked, self.valid)

    @computed_field
    @property
    def full_bypass_rate(self) -> float | None:
        return _rate(self.allowed, self.valid)


class TechniqueRow(_M):
    version: str
    technique: str
    semantic: bool
    n: int
    blocked: int
    downgraded: int

    @computed_field
    @property
    def detection_rate(self) -> float | None:
        return _rate(self.blocked, self.n)

    @computed_field
    @property
    def at_least_warn_rate(self) -> float | None:
        return _rate(self.blocked + self.downgraded, self.n)


class Validity(_M):
    generator: str  # g0 | g1 | seed
    total: int
    statuses: dict[str, int] = Field(default_factory=dict)
    valid: int

    @computed_field
    @property
    def valid_rate(self) -> float | None:
        return _rate(self.valid, self.total)


class Latency(_M):
    version: str
    n: int
    p50_us: int
    p99_us: int
    max_us: int


class Report(_M):
    schema_version: int = 1
    generated_at: str
    versions: tuple[str, ...]
    rules_revs: dict[str, str]
    count_unchecked_as_valid: bool
    detection: tuple[Detection, ...]
    false_positives: tuple[FalsePositives, ...]
    attack_success: tuple[AttackSuccess, ...]
    patch_cost: tuple[PatchCost, ...]
    techniques: tuple[TechniqueRow, ...]
    validity: tuple[Validity, ...]
    generation: tuple[GenerationStats, ...]
    latency: tuple[Latency, ...]
    notes: tuple[str, ...] = ()
