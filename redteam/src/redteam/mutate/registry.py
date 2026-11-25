"""Mutator registry: technique name -> pure functions + the shells they fit.

One technique may have several implementations for disjoint shells (a lure
comment is ``#`` in sh but ``& rem`` in cmd); reports group by technique.
"""

from __future__ import annotations

import random
from collections.abc import Callable
from dataclasses import dataclass

from redteam.models import Shell

from .lex import Unterminated

MutatorFn = Callable[[str, random.Random], str | None]

ALL_SHELLS = frozenset(Shell)
POSIX = frozenset({Shell.SH, Shell.BASH, Shell.ZSH})


@dataclass(frozen=True)
class Mutator:
    technique: str
    shells: frozenset[Shell]
    fn: MutatorFn
    # False: the output is *not* runnable as is (zero-width characters,
    # homoglyphs). Kept because it probes normalization (§5.3.2 "共通"),
    # and reported separately.
    semantic: bool = True

    def __call__(self, payload: str, rng: random.Random) -> str | None:
        try:
            out = self.fn(payload, rng)
        except Unterminated:
            return None
        if out is None or out == payload:
            return None
        return out


REGISTRY: dict[str, list[Mutator]] = {}


def register(
    technique: str,
    shells: frozenset[Shell] | set[Shell],
    semantic: bool = True,
) -> Callable[[MutatorFn], MutatorFn]:
    shells = frozenset(shells)

    def deco(fn: MutatorFn) -> MutatorFn:
        impls = REGISTRY.setdefault(technique, [])
        if any(m.shells & shells for m in impls):
            raise ValueError(f'{technique}: overlapping shells')
        impls.append(Mutator(technique, shells, fn, semantic))
        return fn

    return deco


def get(technique: str, shell: Shell) -> Mutator | None:
    for m in REGISTRY.get(technique, ()):
        if shell in m.shells:
            return m
    return None


def for_shell(shell: Shell, include_non_semantic: bool = True) -> list[Mutator]:
    out = []
    for technique in sorted(REGISTRY):
        m = get(technique, shell)
        if m is not None and (include_non_semantic or m.semantic):
            out.append(m)
    return out


def techniques() -> dict[str, dict[str, object]]:
    """Technique -> shells and whether it preserves semantics."""
    return {
        t: {
            'shells': sorted(s.value for m in impls for s in m.shells),
            'semantic': all(m.semantic for m in impls),
        }
        for t, impls in sorted(REGISTRY.items())
    }
