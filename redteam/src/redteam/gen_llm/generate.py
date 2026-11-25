"""G1: LLM variant generation with engine feedback (phase-5.md §5.3.3).

For each seed: ask the model for ``G1_VARIANTS_PER_CALL`` rewrites, keep the
ones that pass the pydantic schema, optionally syntax-check them, score them,
and while every scored variant is still blocked, retry (up to
``G1_MAX_ATTEMPTS``) showing the model the engine's reason IDs and risk score
for its best previous variant: an adaptive attacker.

Payloads, prompts and responses stay in memory. The audit log gets hashes
and IDs only; nothing here prints or logs text, and pydantic validation
errors (which quote their input) are swallowed, never re-raised.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from redteam.audit import AuditLog, now_ts
from redteam.models import (
    AuditEvent,
    EngineVerdict,
    Seed,
    Shell,
    SyntaxVerdict,
    Variant,
    sha256_hex,
)

from .client import (
    G1_VARIANTS_PER_CALL,
    ChatClient,
    ChatResult,
    G1ClientError,
    request_seed,
)
from .prompts import Feedback, build_messages

G1_MAX_ATTEMPTS = 3
# Refusal rate is judged over the first calls of each model (§5.3.3).
G1_PILOT_CALLS = 20
G1_REFUSAL_THRESHOLD = 0.5
# §5.9: the local primary, then the local model picked in the pilot. The
# last entry of §5.9 (an opencode Zen free model) is a remote endpoint: pass
# it as a ``ChatClient`` with its own base URL if wanted.
G1_FALLBACK_MODELS: tuple[str, ...] = ('qwen3.8:27b-mlx', 'qwen3:0.6b')
G1_MAX_PAYLOAD_CHARS = 16_384
G1_MAX_TECHNIQUE_CHARS = 64
G1_TECHNIQUE_SLUG_CHARS = 40

Scorer = Callable[[list[Variant]], list[EngineVerdict]]
CallStatus = Literal['ok', 'refused', 'invalid_output', 'error']

# Refusal phrasing (English; the prompt is English).
_REFUSAL = re.compile(
    r"\b(?:I\s+(?:can(?:no|')t|cannot|won't|will\s+not|am\s+(?:not\s+able|"
    r"unable|sorry)|'m\s+(?:not\s+able|unable|sorry))|"
    r"(?:can(?:no|')t|cannot|unable\s+to)\s+(?:help|assist|comply|provide|"
    r"create|generate|fulfil)|as\s+an\s+AI\b|against\s+(?:my|the)\s+"
    r'(?:guidelines|policy|policies))',
    re.IGNORECASE,
)
_THINK = re.compile(r'^\s*<think>.*?</think>\s*', re.DOTALL)
_FENCE = re.compile(r'^\s*```[a-zA-Z]*\s*\n?(.*?)\n?```\s*$', re.DOTALL)
_SLUG_BAD = re.compile(r'[^a-z0-9.]+')


class G1Item(BaseModel):
    model_config = ConfigDict(frozen=True, extra='forbid')

    shell: Shell
    payload: str = Field(
        min_length=1, max_length=G1_MAX_PAYLOAD_CHARS, repr=False
    )
    technique: str = Field(min_length=1, max_length=G1_MAX_TECHNIQUE_CHARS)


class G1Output(BaseModel):
    model_config = ConfigDict(frozen=True, extra='forbid')

    variants: list[G1Item] = Field(max_length=G1_VARIANTS_PER_CALL)


@dataclass(frozen=True)
class Parsed:
    status: Literal['ok', 'refused', 'invalid_output']
    items: tuple[G1Item, ...] = ()
    dropped: Counter[str] = field(default_factory=Counter)


def technique_slug(text: str) -> str:
    slug = _SLUG_BAD.sub('-', text.strip().lower().replace('_', '-'))
    slug = re.sub(r'-{2,}', '-', slug).strip('-.')
    return slug[:G1_TECHNIQUE_SLUG_CHARS].rstrip('-.') or 'unspecified'


def _strip_wrappers(content: str) -> str:
    text = _THINK.sub('', content).strip()
    m = _FENCE.match(text)
    return m.group(1).strip() if m else text


def parse_output(
    content: str, seed_payload: str = '', seen: set[str] | None = None
) -> Parsed:
    """Classify one model answer.

    - empty, prose, refusal phrasing, ``variants: []``, or only refusal
      text in the payloads: ``refused``;
    - broken JSON or a schema failure (extra fields, wrong shell, too many
      variants, oversized payload): ``invalid_output``;
    - otherwise ``ok`` with the variants that differ from the seed and from
      ``seen`` (which is updated).
    """
    text = _strip_wrappers(content)
    if not text:
        return Parsed('refused')
    try:
        doc = json.loads(text)
    except ValueError:
        if _REFUSAL.search(text) or '{' not in text:
            return Parsed('refused')
        return Parsed('invalid_output')
    try:
        out = G1Output.model_validate(doc)
    except ValidationError:
        # The error quotes the input; never let it escape.
        if (
            isinstance(doc, dict)
            and _REFUSAL.search(text)
            and not any(isinstance(v, list) and v for v in doc.values())
        ):
            return Parsed('refused')
        return Parsed('invalid_output')
    if not out.variants:
        return Parsed('refused')
    seen = seen if seen is not None else set()
    dropped: Counter[str] = Counter()
    items = []
    refusals = 0
    for item in out.variants:
        if _REFUSAL.search(item.payload) or _REFUSAL.search(item.technique):
            refusals += 1
            dropped['refusal_text'] += 1
        elif item.payload.strip() == seed_payload.strip():
            dropped['unchanged'] += 1
        elif item.payload in seen:
            dropped['duplicate'] += 1
        else:
            seen.add(item.payload)
            items.append(item)
    if refusals == len(out.variants):
        return Parsed('refused', dropped=dropped)
    return Parsed('ok', tuple(items), dropped)


def g1_variant_id(seed_id: str, attempt: int, index: int, sha: str) -> str:
    key = f'{seed_id}|{attempt}|{index}|{sha}'
    return 'g1' + hashlib.sha256(key.encode()).hexdigest()[:18]


@dataclass
class G1Stats:
    calls: int = 0
    refused: int = 0
    invalid_output: int = 0
    errors: Counter[str] = field(default_factory=Counter)
    variants: int = 0
    dropped: Counter[str] = field(default_factory=Counter)
    syntax: Counter[str] = field(default_factory=Counter)
    # attempt -> outcome (blocked / downgraded / bypassed) -> count
    outcomes: dict[int, Counter[str]] = field(default_factory=dict)
    # attempt at which a seed first got a variant that was not blocked
    seeds_evaded_at: Counter[int] = field(default_factory=Counter)
    techniques: Counter[str] = field(default_factory=Counter)
    latency_ms: list[int] = field(default_factory=list)
    tokens_in: int = 0
    tokens_out: int = 0
    per_model: dict[str, Counter[str]] = field(default_factory=dict)

    @property
    def mean_latency_ms(self) -> float:
        if not self.latency_ms:
            return 0.0
        return sum(self.latency_ms) / len(self.latency_ms)

    @property
    def refusal_rate(self) -> float:
        return self.refused / self.calls if self.calls else 0.0

    def as_dict(self) -> dict[str, object]:
        return {
            'calls': self.calls,
            'refused': self.refused,
            'invalid_output': self.invalid_output,
            'errors': dict(self.errors),
            'variants': self.variants,
            'dropped': dict(self.dropped),
            'syntax': dict(sorted(self.syntax.items())),
            'outcomes': {
                str(a): dict(sorted(c.items()))
                for a, c in sorted(self.outcomes.items())
            },
            'seeds_evaded_at': {
                str(a): n for a, n in sorted(self.seeds_evaded_at.items())
            },
            'techniques': dict(self.techniques.most_common()),
            'mean_latency_ms': round(self.mean_latency_ms, 1),
            'tokens_in': self.tokens_in,
            'tokens_out': self.tokens_out,
            'per_model': {m: dict(c) for m, c in self.per_model.items()},
        }


@dataclass(frozen=True)
class ModelSwitch:
    after_calls: int
    from_model: str
    to_model: str
    refusal_rate: float


@dataclass
class GenerationResult:
    variants: list[Variant] = field(default_factory=list)
    syntax: dict[str, SyntaxVerdict] = field(default_factory=dict)
    verdicts: dict[str, EngineVerdict] = field(default_factory=dict)
    stats: G1Stats = field(default_factory=G1Stats)
    models: list[str] = field(default_factory=list)
    switches: list[ModelSwitch] = field(default_factory=list)


class _ModelPool:
    """The active client plus refusal-rate based fallback."""

    def __init__(
        self,
        primary: ChatClient,
        fallbacks: Sequence[str | ChatClient],
        pilot_calls: int,
        threshold: float,
    ) -> None:
        self.current = primary
        self.queue = [
            f
            for f in fallbacks
            if (f if isinstance(f, str) else f.model) != primary.model
        ]
        self.pilot_calls = pilot_calls
        self.threshold = threshold
        self.calls = 0
        self.refused = 0

    def record(self, refused: bool) -> ModelSwitch | None:
        self.calls += 1
        self.refused += int(refused)
        if self.calls != self.pilot_calls or not self.queue:
            return None
        rate = self.refused / self.calls
        if rate <= self.threshold:
            return None
        nxt = self.queue.pop(0)
        old = self.current.info().model_ref
        self.current = (
            self.current.with_model(nxt) if isinstance(nxt, str) else nxt
        )
        self.calls = self.refused = 0
        return ModelSwitch(
            after_calls=self.pilot_calls,
            from_model=old,
            to_model=self.current.info().model_ref,
            refusal_rate=rate,
        )


def current_scorer() -> Scorer:
    """``engine.score`` against the working tree, built once on first use
    (``engine.score_current`` would rebuild the wheel on every call)."""
    from redteam import engine

    build = None

    def scorer(items: list[Variant]) -> list[EngineVerdict]:
        nonlocal build
        if build is None:
            build = engine.prepare_current()
        return engine.score(items, build)

    return scorer


def _syntax_ok(verdict: SyntaxVerdict) -> str:
    from redteam.validate import effective_status

    return effective_status(verdict)


def _syntax_error_ids(verdicts: Iterable[SyntaxVerdict]) -> tuple[str, ...]:
    from redteam.validate import flatten_errors

    ids: list[str] = []
    for v in verdicts:
        for issue in flatten_errors(v):
            if issue.id not in ids:
                ids.append(issue.id)
    return tuple(ids[:8])


class _Audit:
    def __init__(self, log: AuditLog | None, run_id: str, round: int):
        self.log = log
        self.run_id = run_id
        self.round = round
        self.buffer: list[AuditEvent] = []

    def add(self, **kw: object) -> None:
        if self.log is not None:
            self.buffer.append(
                AuditEvent(
                    ts=now_ts(), run_id=self.run_id, round=self.round, **kw
                )
            )

    def flush(self) -> None:
        if self.log is not None and self.buffer:
            self.log.extend(self.buffer)
        self.buffer = []


def generate_g1(
    seeds: Iterable[Seed],
    *,
    run_seed: int,
    round: int,
    client: ChatClient,
    scorer: Scorer | None = None,
    validator: object | None = None,
    attempts: int = G1_MAX_ATTEMPTS,
    audit: AuditLog | None = None,
    run_id: str | None = None,
    fallback_models: Sequence[str | ChatClient] = (),
    pilot_calls: int = G1_PILOT_CALLS,
    refusal_threshold: float = G1_REFUSAL_THRESHOLD,
) -> GenerationResult:
    """Generate G1 variants for ``seeds``.

    ``scorer`` maps variants to verdicts (default: the working-tree engine,
    see ``current_scorer``). ``validator`` is anything with
    ``validate(payload, shell) -> SyntaxVerdict`` (``redteam.validate.
    Validator``); syntax-invalid variants are kept but not scored and never
    count as bypasses. ``fallback_models``: if more than
    ``refusal_threshold`` of the first ``pilot_calls`` calls of a model are
    refusals, switch to the next one (model names reuse ``client``'s
    endpoint).
    """
    scorer = scorer or current_scorer()
    if run_id is None:
        run_id = audit.path.parent.name if audit is not None else 'g1'
    log = _Audit(audit, run_id, round)
    pool = _ModelPool(client, fallback_models, pilot_calls, refusal_threshold)
    result = GenerationResult()
    stats = result.stats

    for seed in seeds:
        seen: set[str] = set()
        feedback: Feedback | None = None
        parent: str | None = None
        for attempt in range(1, attempts + 1):
            active = pool.current
            model_ref = active.info().model_ref
            if model_ref not in result.models:
                result.models.append(model_ref)
            per_model = stats.per_model.setdefault(model_ref, Counter())
            messages = build_messages(
                seed.payload, seed.shell, attempt=attempt, feedback=feedback
            )
            seed_int = request_seed(run_seed, seed.case_id, attempt)
            stats.calls += 1
            per_model['calls'] += 1
            call: ChatResult | None = None
            try:
                call = active.complete(messages, seed_int)
            except G1ClientError as e:
                stats.errors[e.kind] += 1
                per_model['errors'] += 1
                log.add(
                    actor='red-g1',
                    event='llm_call',
                    model=model_ref,
                    params={
                        'temperature': active.temperature,
                        'seed': seed_int,
                    },
                    result={
                        'seed_id': seed.case_id,
                        'attempt': attempt,
                        'status': 'error',
                        'error': e.kind,
                    },
                )
                parsed = Parsed('invalid_output')
                status: CallStatus = 'error'
            else:
                parsed = parse_output(call.content, seed.payload, seen)
                status = parsed.status
                stats.latency_ms.append(call.latency_ms)
                stats.tokens_in += call.tokens_in
                stats.tokens_out += call.tokens_out
                stats.dropped.update(parsed.dropped)
                log.add(
                    actor='red-g1',
                    event='llm_call',
                    model=model_ref,
                    params=call.params,
                    prompt_sha256=call.prompt_sha256,
                    response_sha256=call.response_sha256,
                    result={
                        'seed_id': seed.case_id,
                        'attempt': attempt,
                        'status': status,
                        'variants': len(parsed.items),
                        'finish_reason': call.finish_reason,
                    },
                    duration_ms=call.latency_ms,
                    tokens={'in': call.tokens_in, 'out': call.tokens_out},
                )
            if status == 'refused':
                stats.refused += 1
                per_model['refused'] += 1
            elif status == 'invalid_output':
                stats.invalid_output += 1
                per_model['invalid_output'] += 1

            switch = pool.record(status == 'refused')
            if switch is not None:
                result.switches.append(switch)
                log.add(
                    actor='orchestrator',
                    event='model_switch',
                    model=switch.to_model,
                    result={
                        'from': switch.from_model,
                        'refusal_rate': float(f'{switch.refusal_rate:.3f}'),
                        'after_calls': switch.after_calls,
                    },
                )

            if status == 'refused':
                break  # §5.3.3: refusals are not retried
            if call is None or not parsed.items:
                continue

            variants = []
            for index, item in enumerate(parsed.items):
                sha = sha256_hex(item.payload)
                slug = technique_slug(item.technique)
                variants.append(
                    Variant(
                        id=g1_variant_id(seed.case_id, attempt, index, sha),
                        seed_id=seed.case_id,
                        parent_id=parent,
                        round=round,
                        generator='g1',
                        techniques=(slug,),
                        shell=item.shell,
                        model=model_ref,
                        payload=item.payload,
                    )
                )
                stats.techniques[slug] += 1
            stats.variants += len(variants)
            result.variants.extend(variants)
            for v in variants:
                log.add(
                    actor='red-g1',
                    event='generate',
                    variant_id=v.id,
                    payload_sha256=v.payload_sha256,
                    model=model_ref,
                    params=call.params,
                    prompt_sha256=call.prompt_sha256,
                    response_sha256=call.response_sha256,
                    result={
                        'seed_id': seed.case_id,
                        'attempt': attempt,
                        'parent_id': parent,
                    },
                )

            scorable = variants
            invalid_syntax: list[SyntaxVerdict] = []
            if validator is not None:
                scorable = []
                for v in variants:
                    sv = validator.validate(v.payload, v.shell)
                    result.syntax[v.id] = sv
                    eff = _syntax_ok(sv)
                    stats.syntax[eff] += 1
                    log.add(
                        actor='validator',
                        event='validate',
                        variant_id=v.id,
                        payload_sha256=v.payload_sha256,
                        result={'syntax_ok': eff == 'ok', 'status': eff},
                    )
                    if eff in ('ok', 'unchecked'):
                        scorable.append(v)
                    else:
                        invalid_syntax.append(sv)

            verdicts = scorer(scorable) if scorable else []
            outcomes = stats.outcomes.setdefault(attempt, Counter())
            by_id = {v.id: v for v in scorable}
            for verdict in verdicts:
                result.verdicts[verdict.variant_id] = verdict
                outcomes[verdict.outcome] += 1
                v = by_id.get(verdict.variant_id)
                log.add(
                    actor='engine',
                    event='detect',
                    variant_id=verdict.variant_id,
                    payload_sha256=v.payload_sha256 if v else None,
                    rules_rev=verdict.rules_rev,
                    result={
                        'action': verdict.action,
                        'level': verdict.level,
                        'risk_score': verdict.risk_score,
                        'reason_ids': list(verdict.reason_ids),
                    },
                    duration_ms=verdict.duration_us // 1000,
                )

            if any(v.outcome != 'blocked' for v in verdicts):
                stats.seeds_evaded_at[attempt] += 1
                break  # adaptive attacker: only retry while blocked
            if verdicts:
                best = min(verdicts, key=lambda v: v.risk_score)
                feedback = Feedback(
                    action=best.action,
                    risk_score=best.risk_score,
                    reason_ids=best.reason_ids,
                )
                parent = best.variant_id
            elif invalid_syntax:
                feedback = Feedback(
                    action='none',
                    risk_score=0,
                    syntax_error_ids=_syntax_error_ids(invalid_syntax)
                    or ('syntax-invalid',),
                )
                parent = variants[0].id
        log.flush()
    log.flush()
    return result
