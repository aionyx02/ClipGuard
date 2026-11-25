"""G0 composer: stack up to ``G0_MAX_DEPTH`` mutators per variant.

Everything derives from the run seed: variant ``k`` of seed ``s`` uses
``Random(derive_seed(run_seed, s, k))``, so a run is reproducible and a
single variant can be regenerated on its own.
"""

from __future__ import annotations

import hashlib
import random
from collections.abc import Iterable

from redteam.models import Seed, Variant

from .registry import Mutator, for_shell

G0_VARIANTS_PER_SEED = 20
G0_MAX_DEPTH = 3
# Tries per wanted variant before giving up on a seed (duplicates and
# chains where nothing applies are retried with the next index).
G0_ATTEMPTS_FACTOR = 3


def derive_seed(run_seed: int, seed_id: str, index: int) -> int:
    digest = hashlib.sha256(f'{run_seed}:{seed_id}:{index}'.encode()).digest()
    return int.from_bytes(digest[:8], 'big')


def variant_id(seed_id: str, chain: Iterable[str], rng_seed: int) -> str:
    key = f'{seed_id}|{"+".join(chain)}|{rng_seed}'
    return 'g0' + hashlib.sha256(key.encode()).hexdigest()[:18]


def mutate_chain(
    payload: str,
    mutators: list[Mutator],
    rng: random.Random,
    depth: int,
) -> tuple[str, tuple[str, ...]]:
    """Apply up to ``depth`` distinct techniques; returns (payload, chain)."""
    chain: list[str] = []
    for _ in range(depth):
        candidates = [m for m in mutators if m.technique not in chain]
        rng.shuffle(candidates)
        for m in candidates:
            out = m(payload, rng)
            if out is not None:
                payload = out
                chain.append(m.technique)
                break
        else:
            break
    return payload, tuple(chain)


def generate_g0(
    seeds: Iterable[Seed],
    run_seed: int,
    round: int = 1,
    per_seed: int = G0_VARIANTS_PER_SEED,
    max_depth: int = G0_MAX_DEPTH,
    include_non_semantic: bool = True,
) -> list[Variant]:
    out = []
    for seed in seeds:
        mutators = for_shell(seed.shell, include_non_semantic)
        seen = {seed.payload}
        made = 0
        for index in range(per_seed * G0_ATTEMPTS_FACTOR):
            if made >= per_seed:
                break
            rng_seed = derive_seed(run_seed, seed.case_id, index)
            rng = random.Random(rng_seed)  # noqa: S311
            depth = rng.randint(1, max_depth)
            payload, chain = mutate_chain(seed.payload, mutators, rng, depth)
            if not chain or payload in seen:
                continue
            seen.add(payload)
            made += 1
            out.append(
                Variant(
                    id=variant_id(seed.case_id, chain, rng_seed),
                    seed_id=seed.case_id,
                    round=round,
                    generator='g0',
                    techniques=chain,
                    shell=seed.shell,
                    payload=payload,
                )
            )
    return out
