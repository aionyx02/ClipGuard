"""G0 mutators for sh / bash / zsh (phase-5.md §5.3.2).

Only top-level unquoted words are rewritten, and only "plain" words (no
globs, ``=``, ``~``, ``$`` or escapes), so quoting a piece of a word cannot
change expansion. ``$'...'`` needs bash or zsh; ``${IFS}`` splitting needs
sh or bash (zsh does not split unquoted expansions).
"""

from __future__ import annotations

import base64
import random

from redteam.models import Shell

from . import _kw
from .lex import (
    SH_KEYWORDS,
    Tok,
    is_sh_plain,
    lex_sh,
    sh_command_words,
)
from .registry import POSIX, register

INTERPRETER = {Shell.SH: 'sh', Shell.BASH: 'ba' + 'sh', Shell.ZSH: 'z' + 'sh'}


def _plain_words(toks: list[Tok]) -> list[int]:
    out = []
    for idx, t in enumerate(toks):
        if t.kind != 'word' or not is_sh_plain(t.text):
            continue
        prev = toks[idx - 1] if idx else None
        nxt = toks[idx + 1] if idx + 1 < len(toks) else None
        # Glued to a quote or expansion: part of a larger word.
        if prev is not None and prev.kind not in ('ws', 'nl', 'op'):
            continue
        if nxt is not None and nxt.kind not in ('ws', 'nl', 'op', 'comment'):
            continue
        # `2>&1`: a file descriptor number.
        if t.text.isdigit() and nxt is not None and nxt.kind == 'op':
            continue
        out.append(idx)
    return out


def ansi_c(word: str) -> str:
    return "$'" + ''.join(f'\\x{b:02x}' for b in word.encode()) + "'"


def _ansi_c_mutator(payload: str, rng: random.Random) -> str | None:
    toks = lex_sh(payload)
    words = _plain_words(toks)
    if not words:
        return None
    cmd = [i for i in sh_command_words(toks) if i in words]
    idx = rng.choice(cmd if cmd and rng.random() < 0.6 else words)
    t = toks[idx]
    return payload[: t.start] + ansi_c(t.text) + payload[t.end :]


register('sh.ansi_c', {Shell.BASH, Shell.ZSH})(_ansi_c_mutator)


def _redirect_target(toks: list[Tok], idx: int) -> bool:
    j = idx - 1
    while j >= 0 and toks[j].kind == 'ws':
        j -= 1
    return j >= 0 and toks[j].kind == 'op' and toks[j].text[-1] in '<>&'


@register('sh.ifs', {Shell.SH, Shell.BASH})
def ifs(payload: str, rng: random.Random) -> str | None:
    """``curl -s x`` -> ``curl${IFS}-s x`` (default IFS splits it back)."""
    toks = lex_sh(payload)
    spots = []
    for idx in range(1, len(toks) - 1):
        t, prev, nxt = toks[idx], toks[idx - 1], toks[idx + 1]
        if t.kind != 'ws' or t.text != ' ':
            continue
        if prev.kind not in ('word', 'sq', 'dq') or nxt.kind not in (
            'word',
            'sq',
            'dq',
        ):
            continue
        if prev.text in SH_KEYWORDS or nxt.text in SH_KEYWORDS:
            continue
        if '=' in prev.text or '=' in nxt.text:
            continue
        if _redirect_target(toks, idx - 1):
            continue
        after = toks[idx + 2] if idx + 2 < len(toks) else None
        if after is not None and after.kind == 'op' and after.text[0] in '<>':
            # `cmd 2>&1`: the fd number must stay its own word.
            continue
        spots.append(t)
    if not spots:
        return None
    picks = rng.sample(spots, k=min(len(spots), rng.randint(1, 3)))
    for t in sorted(picks, key=lambda t: -t.start):
        payload = payload[: t.start] + '${IFS}' + payload[t.end :]
    return payload


@register('sh.quote_split', POSIX)
def quote_split(payload: str, rng: random.Random) -> str | None:
    """``curl`` -> ``c''url`` / ``cu""rl``."""
    toks = lex_sh(payload)
    words = [i for i in _plain_words(toks) if len(toks[i].text) >= 2]
    if not words:
        return None
    t = toks[rng.choice(words)]
    at = t.start + rng.randint(1, len(t.text) - 1)
    quote = rng.choice(["''", '""'])
    return payload[:at] + quote + payload[at:]


def base64_pipe(payload: str, interpreter: str) -> str | None:
    """``x`` -> ``echo <base64 of x> | base64 -d | <interpreter>``."""
    lex_sh(payload)
    if not payload.strip():
        return None
    b64 = base64.b64encode(payload.encode()).decode('ascii')
    return f'echo {b64} | {_kw.BASE64} -d | {interpreter}'


# bash runs sh scripts too; zsh payloads go back to zsh.
register('sh.base64_pipe', {Shell.SH, Shell.BASH})(
    lambda payload, rng: base64_pipe(payload, INTERPRETER[Shell.BASH])
)
register('sh.base64_pipe', {Shell.ZSH})(
    lambda payload, rng: base64_pipe(payload, INTERPRETER[Shell.ZSH])
)


@register('sh.eval', POSIX)
def eval_wrap(payload: str, rng: random.Random) -> str | None:
    """``x`` -> ``eval 'x'`` (single quotes keep every byte)."""
    lex_sh(payload)
    script = payload.strip()
    if not script:
        return None
    return "eval '" + script.replace("'", "'\\''") + "'"


@register('sh.var_indirection', POSIX)
def var_indirection(payload: str, rng: random.Random) -> str | None:
    """``curl x`` -> ``_v=curl; $_v x``."""
    toks = lex_sh(payload)
    plain = set(_plain_words(toks))
    cmds = [i for i in sh_command_words(toks) if i in plain]
    if not cmds or payload.lstrip().startswith(('#!', '`')):
        return None
    t = toks[rng.choice(cmds)]
    name = '_' + ''.join(rng.choice('abcdefghjkmnpqrstuvwxyz') for _ in '123')
    if name in payload:
        return None
    body = payload[: t.start] + '$' + name + payload[t.end :]
    return f'{name}={t.text}; {body}'


def unquote_sh_word(word: str) -> str:
    """Reference for tests: quote removal for the forms these mutators emit."""
    out = []
    i = 0
    while i < len(word):
        if word.startswith("$'", i):
            j = word.index("'", i + 2)
            raw = word[i + 2 : j]
            out.append(bytes(int(h, 16) for h in raw.split('\\x')[1:]).decode())
            i = j + 1
        elif word[i] in '\'"':
            j = word.index(word[i], i + 1)
            out.append(word[i + 1 : j])
            i = j + 1
        else:
            out.append(word[i])
            i += 1
    return ''.join(out)
