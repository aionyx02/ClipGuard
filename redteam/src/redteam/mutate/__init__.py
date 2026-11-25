"""G0: deterministic, semantics-preserving mutators (phase-5.md §5.3.2).

Each mutator is a pure ``(payload, rng) -> payload | None`` function
(``None``: not applicable). Importing this package registers all of them.
"""

from . import cmd, common, posix, ps  # noqa: F401  (registration)
from .compose import (
    G0_MAX_DEPTH,
    G0_VARIANTS_PER_SEED,
    derive_seed,
    generate_g0,
    mutate_chain,
    variant_id,
)
from .registry import REGISTRY, Mutator, for_shell, get, techniques

__all__ = [
    'G0_MAX_DEPTH',
    'G0_VARIANTS_PER_SEED',
    'REGISTRY',
    'Mutator',
    'derive_seed',
    'for_shell',
    'generate_g0',
    'get',
    'mutate_chain',
    'techniques',
    'variant_id',
]
