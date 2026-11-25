"""G0 mutators for cmd.exe (phase-5.md §5.3.2).

Semantics are those of a line typed (or pasted) at an interactive ``cmd``
prompt: undefined ``%var%`` stays literal, carets outside quotes escape the
next character. To stay equivalent by construction the mutators only touch
unquoted text, never touch words containing ``%`` or ``!``, and refuse lines
with an unquoted pipe (pipe sides are re-parsed by child ``cmd`` processes).
"""

from __future__ import annotations

import random

from redteam.models import Shell

from .lex import (
    CMD_BUILTINS,
    Unterminated,
    cmd_first_word,
    cmd_has_unquoted,
    cmd_quote_mask,
    splice,
)
from .registry import register

CMD = frozenset({Shell.CMD})

# Characters of the tail of %COMSPEC% (``...\system32\cmd.exe``), counted
# from the end, so ``%COMSPEC:~-7,1%`` is ``c``. The tail is the same on
# every Windows install; the drive and ``Windows`` casing are not, so only
# negative offsets inside ``system32\cmd.exe`` are used.
_COMSPEC_TAIL = 'system32\\cmd.exe'
COMSPEC_OFFSETS: dict[str, int] = {}
for _k, _ch in enumerate(reversed(_COMSPEC_TAIL), 1):
    if _ch.isalpha():
        COMSPEC_OFFSETS.setdefault(_ch, -_k)


def _no_pipe(payload: str) -> bool:
    return not cmd_has_unquoted(payload, '|')


def _program_word(payload: str):
    """The first word, if it is a plain unquoted program name."""
    w = cmd_first_word(payload)
    if w is None or any(c in w.text for c in '"^%!'):
        return None
    return w


def _is_builtin(word: str) -> bool:
    return word.lower() in CMD_BUILTINS


@register('cmd.caret', CMD)
def caret(payload: str, rng: random.Random) -> str | None:
    """``notepad`` -> ``no^tepad``: a caret before an ordinary character."""
    if not _no_pipe(payload) or '\n' in payload.strip('\r\n'):
        return None
    mask = cmd_quote_mask(payload)
    spots = []
    word_start = 0
    for i, ch in enumerate(payload):
        if ch in ' \t':
            word_start = i + 1
            continue
        if (
            mask[i]
            and ch.isascii()
            and ch.isalnum()
            and i > word_start
            and payload[i - 1] != '^'
        ):
            spots.append((i, word_start))
    word_end = {}
    spots = [
        (i, s) for i, s in spots if not _word_has(payload, s, word_end, '%!')
    ]
    if not spots:
        return None
    picks = rng.sample(spots, k=min(len(spots), rng.randint(1, 4)))
    for i, _ in sorted(picks, reverse=True):
        payload = splice(payload, i, i, '^')
    return payload


def _word_has(text: str, start: int, cache: dict, chars: str) -> bool:
    if start not in cache:
        end = start
        while end < len(text) and text[end] not in ' \t':
            end += 1
        cache[start] = any(c in chars for c in text[start:end])
    return cache[start]


@register('cmd.empty_quotes', CMD)
def empty_quotes(payload: str, rng: random.Random) -> str | None:
    """``notepad`` -> ``no""tepad`` in the program name (not builtins)."""
    w = _program_word(payload)
    if w is None or _is_builtin(w.text) or len(w.text) < 2:
        return None
    if not _no_pipe(payload):
        return None
    at = w.start + rng.randint(1, len(w.text) - 1)
    return splice(payload, at, at, '""')


@register('cmd.substring', CMD)
def substring(payload: str, rng: random.Random) -> str | None:
    """A letter of the program name becomes ``%COMSPEC:~-N,1%``.

    Command names are case-insensitive, so the lowercase letters of the
    ``system32\\cmd.exe`` tail can stand for either case.
    """
    w = _program_word(payload)
    if w is None:
        return None
    spots = [
        w.start + k
        for k, ch in enumerate(w.text)
        if ch.lower() in COMSPEC_OFFSETS and ch.isascii()
    ]
    if not spots:
        return None
    picks = rng.sample(spots, k=min(len(spots), rng.randint(1, 2)))
    for i in sorted(picks, reverse=True):
        off = COMSPEC_OFFSETS[payload[i].lower()]
        payload = splice(payload, i, i + 1, f'%COMSPEC:~{off},1%')
    return payload


@register('cmd.set_indirection', CMD)
def set_indirection(payload: str, rng: random.Random) -> str | None:
    """``prog args`` -> ``set "_x=prog" & call %_x% args``.

    On an interactive line the undefined ``%_x%`` survives the first
    expansion and ``call`` expands it after ``set`` ran. ``call`` re-parses
    the rest, so the rest must not contain ``%``, ``!``, ``^`` or pipes and
    redirections.
    """
    w = _program_word(payload)
    if w is None or _is_builtin(w.text) or '\n' in payload.strip('\r\n'):
        return None
    rest = payload[w.end :]
    if any(c in rest for c in '%!^|<>'):
        return None
    name = '_' + ''.join(rng.choice('abcdefghijkmnpqrstuvwxyz') for _ in '123')
    if name.lower() in payload.lower():
        return None
    head = payload[: w.start]
    return f'{head}set "{name}={w.text}" & call %{name}%{rest}'


@register('cmd.wrap', CMD)
def wrap(payload: str, rng: random.Random) -> str | None:
    """``x`` -> ``cmd /s /c "x"`` (``/s`` strips exactly the outer quotes).

    The outer quotes flip the quote state of the payload for the outer
    parse, so quoted parts must not hold operators, and ``%`` would be
    expanded twice.
    """
    if '%' in payload or '!' in payload or '\n' in payload.strip('\r\n'):
        return None
    mask = cmd_quote_mask(payload)
    for i, ch in enumerate(payload):
        if not mask[i] and ch in '&|<>()^':
            return None
    exe = rng.choice(['c' + 'md', 'C' + 'MD', 'c' + 'md.exe'])
    flags = rng.choice(['/s /c', '/S /C', '/d /s /c'])
    return f'{exe} {flags} "{payload.strip()}"'


@register('cmd.case', CMD)
def case(payload: str, rng: random.Random) -> str | None:
    """Random case for the (case-insensitive) program name."""
    w = _program_word(payload)
    if w is None:
        return None
    word = ''.join(
        c.upper() if rng.random() < 0.5 else c.lower() for c in w.text
    )
    if word == w.text:
        word = w.text.swapcase()
    return splice(payload, w.start, w.end, word)


def unescape_carets(text: str) -> str:
    """Reference for tests: what cmd's phase 2 does to unquoted carets."""
    out = []
    quoted = False
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == '"':
            quoted = not quoted
        elif ch == '^' and not quoted and i + 1 < len(text):
            out.append(text[i + 1])
            i += 2
            continue
        out.append(ch)
        i += 1
    if quoted:
        raise Unterminated('double quote')
    return ''.join(out)
