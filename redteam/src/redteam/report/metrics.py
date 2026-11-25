"""The four metrics of phase-5.md §5.4, plus the auxiliary numbers."""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from datetime import UTC, datetime

from redteam.engine import percentile
from redteam.models import (
    EngineVerdict,
    Seed,
    Split,
    SyntaxVerdict,
    Variant,
)

from .models import (
    AttackSuccess,
    Detection,
    FalsePositives,
    GenerationStats,
    Latency,
    PatchCost,
    Report,
    RoundInput,
    ScoredItem,
    TechniqueRow,
    Validity,
    VersionInput,
)


def _non_semantic() -> set[str]:
    from redteam.mutate import techniques

    return {t for t, info in techniques().items() if not info['semantic']}


def join(
    variants: Iterable[Variant | Seed],
    verdicts: Iterable[EngineVerdict],
    splits: Mapping[str, Split] | None = None,
    syntax: Mapping[str, SyntaxVerdict] | None = None,
    equivalence: Mapping[str, str] | None = None,
) -> list[ScoredItem]:
    """Join variants (or seeds) with their engine and syntax verdicts.

    ``splits`` maps seed id -> split (defaults to the stable sha256 split).
    Items without an engine verdict are dropped.
    """
    from redteam.seeds import split_for

    by_id = {v.variant_id: v for v in verdicts}
    syntax = syntax or {}
    equivalence = equivalence or {}
    probes = _non_semantic()
    out = []
    for x in variants:
        if isinstance(x, Seed):
            vid, seed_id, rnd, gen, techs = x.case_id, x.case_id, 0, None, ()
        else:
            vid, seed_id, rnd = x.id, x.seed_id, x.round
            gen, techs = x.generator, x.techniques
        verdict = by_id.get(vid)
        if verdict is None:
            continue
        split = (splits or {}).get(seed_id) or split_for(seed_id)
        sv = syntax.get(vid)
        status = None
        if sv is not None:
            status = 'ok' if sv.ok else sv.status
            if sv.status == 'ok' and not sv.ok:
                status = 'invalid'
        out.append(
            ScoredItem(
                variant_id=vid,
                seed_id=seed_id,
                split=split,
                round=rnd,
                generator=gen,
                techniques=techs,
                shell=x.shell,
                semantic=not any(t in probes for t in techs),
                syntax_status=status,
                equivalence=equivalence.get(vid),
                action=verdict.action,
                level=verdict.level,
                risk_score=verdict.risk_score,
                reason_ids=verdict.reason_ids,
                duration_us=verdict.duration_us,
            )
        )
    return out


def is_valid(item: ScoredItem, count_unchecked_as_valid: bool) -> bool:
    """Syntax-valid. Items never sent to a validator (``None``) count as
    valid: G0 is equivalent by construction and seeds are corpus cases."""
    if item.syntax_status in (None, 'ok'):
        return True
    return item.syntax_status == 'unchecked' and count_unchecked_as_valid


def detection(
    version: str,
    items: Iterable[ScoredItem],
    split: Split,
    count_unchecked_as_valid: bool = True,
) -> Detection:
    valid = [
        i
        for i in items
        if i.split == split and is_valid(i, count_unchecked_as_valid)
    ]
    c = Counter(i.action for i in valid)
    return Detection(
        version=version,
        split=split,
        valid=len(valid),
        blocked=c['quarantine'],
        downgraded=c['warn'],
        bypassed=c['allow'],
    )


def false_positives(
    version: str, dataset: str, actions: Sequence[str]
) -> FalsePositives:
    c = Counter(actions)
    return FalsePositives(
        version=version,
        dataset=dataset,
        n=len(actions),
        warn=c['warn'],
        quarantine=c['quarantine'],
    )


def attack_success(
    rnd: RoundInput, count_unchecked_as_valid: bool = True
) -> list[AttackSuccess]:
    out = []
    for gen in ('g0', 'g1'):
        valid = [
            i
            for i in rnd.items
            if i.generator == gen
            and i.split == 'train'
            and is_valid(i, count_unchecked_as_valid)
        ]
        if not valid:
            continue
        not_blocked = [i for i in valid if i.action != 'quarantine']
        out.append(
            AttackSuccess(
                round=rnd.round,
                version=rnd.version,
                generator=gen,
                valid=len(valid),
                not_blocked=len(not_blocked),
                allowed=sum(1 for i in valid if i.action == 'allow'),
                confirmed_equivalent=sum(
                    1 for i in not_blocked if i.equivalence == 'equivalent'
                ),
                unconfirmed=sum(
                    1
                    for i in not_blocked
                    if gen == 'g1' and i.equivalence != 'equivalent'
                ),
            )
        )
    return out


def per_technique(
    version: str, items: Iterable[ScoredItem], count_unchecked_as_valid=True
) -> list[TechniqueRow]:
    probes = _non_semantic()
    acc: dict[str, Counter[str]] = defaultdict(Counter)
    for i in items:
        if not is_valid(i, count_unchecked_as_valid):
            continue
        for t in set(i.techniques):
            acc[t][i.action] += 1
    return [
        TechniqueRow(
            version=version,
            technique=t,
            semantic=t not in probes,
            n=sum(c.values()),
            blocked=c['quarantine'],
            downgraded=c['warn'],
        )
        for t, c in sorted(acc.items())
    ]


def validity(items: Iterable[ScoredItem], count_unchecked_as_valid=True):
    groups: dict[str, list[ScoredItem]] = defaultdict(list)
    for i in items:
        groups[i.generator or 'seed'].append(i)
    out = []
    for gen, rows in sorted(groups.items()):
        statuses = Counter(i.syntax_status or 'not_validated' for i in rows)
        out.append(
            Validity(
                generator=gen,
                total=len(rows),
                statuses=dict(sorted(statuses.items())),
                valid=sum(
                    1 for i in rows if is_valid(i, count_unchecked_as_valid)
                ),
            )
        )
    return out


def latency(version: str, items: Iterable[ScoredItem]) -> Latency:
    d = [i.duration_us for i in items]
    return Latency(
        version=version,
        n=len(d),
        p50_us=percentile(d, 50),
        p99_us=percentile(d, 99),
        max_us=max(d, default=0),
    )


def build_report(
    versions: Sequence[VersionInput],
    rounds: Sequence[RoundInput] = (),
    patch_costs: Sequence[PatchCost] = (),
    generation: Sequence[GenerationStats] = (),
    count_unchecked_as_valid: bool = True,
    generated_at: str | None = None,
    notes: Sequence[str] = (),
) -> Report:
    cv = count_unchecked_as_valid
    det, fps, techs, lat = [], [], [], []
    for v in versions:
        for split in ('heldout', 'train'):
            det.append(detection(v.label, v.items, split, cv))
        corpus = list(v.benign_corpus)
        extra = list(v.benign_extra)
        fps.append(false_positives(v.label, 'corpus', corpus))
        if extra:
            fps.append(false_positives(v.label, 'extra', extra))
        fps.append(false_positives(v.label, 'all', corpus + extra))
        techs += per_technique(v.label, v.items, cv)
        heldout = [i for i in v.items if i.split == 'heldout']
        lat.append(latency(v.label, heldout or v.items))
    attack = [a for r in rounds for a in attack_success(r, cv)]
    all_items = [i for v in versions for i in v.items] + [
        i for r in rounds for i in r.items
    ]
    seen: dict[str, ScoredItem] = {}
    for i in all_items:
        seen.setdefault(i.variant_id, i)
    return Report(
        generated_at=generated_at
        or datetime.now(UTC).isoformat(timespec='seconds'),
        versions=tuple(v.label for v in versions),
        rules_revs={v.label: v.rules_rev for v in versions},
        count_unchecked_as_valid=cv,
        detection=tuple(det),
        false_positives=tuple(fps),
        attack_success=tuple(attack),
        patch_cost=tuple(patch_costs),
        techniques=tuple(techs),
        validity=tuple(validity(seen.values(), cv)),
        generation=tuple(generation),
        latency=tuple(lat),
        notes=tuple(notes),
    )
