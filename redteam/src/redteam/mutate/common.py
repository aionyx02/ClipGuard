"""G0 mutators shared by every shell (phase-5.md §5.3.2 "共通")."""

from __future__ import annotations

import random
import re

from redteam.models import Shell

from .lex import (
    Tok,
    cmd_has_unquoted,
    cmd_quote_mask,
    lex_ps,
    lex_sh,
    ps_command_words,
    sh_command_words,
)
from .registry import ALL_SHELLS, POSIX, register

# Mirrors paste_warden_core::limits::MAX_ANALYZED_CHARS and the verdict
# window (crates/core/src/{limits.rs,command/verdict.rs}).
READ_LIMIT_CHARS = 1 << 20
WINDOW_CHARS = 4096

PAD_SIZES = (8, 64, 512, WINDOW_CHARS + 1, READ_LIMIT_CHARS + 1)
PAD_WEIGHTS = (4, 4, 3, 3, 1)


def _pad(rng: random.Random, chars: str) -> str:
    size = rng.choices(PAD_SIZES, PAD_WEIGHTS)[0]
    ch = rng.choice(chars)
    return ch * size


def _cmd_last_is_set(payload: str) -> bool:
    last = re.split(r'&&?|\n', payload.rstrip())[-1].strip().lower()
    return last.startswith('set ') or last.startswith('set"')


@register('common.padding', ALL_SHELLS)
def padding(payload: str, rng: random.Random) -> str | None:
    """Leading or trailing whitespace, up to past the engine's read limit."""
    where = rng.choice(['leading', 'trailing'])
    if where == 'leading':
        return _pad(rng, ' \t\n') + payload
    # Trailing spaces would end up in a final `set x=...` value.
    if _cmd_last_is_set(payload) or payload.rstrip().endswith(('`', '^', '\\')):
        return None
    return payload + _pad(rng, ' \t')


LURES = (
    'I am not a robot - reCAPTCHA Verification ID: {n}',
    '我不是機器人 驗證 ID: {n}',
    '人机验证 ID: {n}',
    '私はロボットではありません 認証 ID: {n}',
    '나는 로봇이 아닙니다 인증 ID: {n}',
    'No soy un robot - verificación ID: {n}',
    'Je ne suis pas un robot - vérification ID : {n}',
    'Ich bin kein Roboter - Verifizierung ID: {n}',
    'Я не робот - верификация ID: {n}',
    'Tôi không phải là người máy - xác minh ID: {n}',
    'Press Enter to complete human verification ({n})',
    'Cloudflare: verify you are human. Ray ID {n}',
)


def _comment_prefix(shell: Shell) -> str:
    if shell == Shell.CMD:
        return ' & rem '
    if shell == Shell.APPLESCRIPT:
        return ' -- '
    return ' # '


def _trailing_comment(payload: str, shell: Shell) -> Tok | None:
    if shell in POSIX or shell == Shell.POWERSHELL:
        toks = lex_sh(payload) if shell in POSIX else lex_ps(payload)
        for t in reversed(toks):
            if t.kind in ('ws', 'nl'):
                continue
            return t if t.kind == 'comment' else None
    return None


def _decoy(shell: Shell):
    def run(payload: str, rng: random.Random) -> str | None:
        lure = rng.choice(LURES).format(n=rng.randint(1000, 9999))
        existing = _trailing_comment(payload, shell)
        if existing is not None:
            return (
                payload[: existing.start]
                + '# '
                + lure
                + payload[existing.end :]
            )
        if shell == Shell.CMD and (
            _cmd_last_is_set(payload) or '\n' in payload.strip()
        ):
            return None
        if shell == Shell.CMD:
            cmd_quote_mask(payload)  # refuses an open quote
        body = payload.rstrip()
        if body.endswith(('`', '^', '\\')):
            return None
        pad = ' ' * rng.choice([1, 8, 40]) if shell != Shell.CMD else ''
        return body + pad + _comment_prefix(shell) + lure

    return run


for _shell in Shell:
    register('common.decoy_comment', {_shell})(_decoy(_shell))


# --- normalization probes (not runnable as is) --------------------------------

ZERO_WIDTH = ('​', '‌', '‍', '⁠', '﻿', '­')
HOMOGLYPHS = {
    'a': 'а',
    'c': 'с',
    'e': 'е',
    'i': 'і',
    'o': 'о',
    'p': 'р',
    's': 'ѕ',
    'x': 'х',
    'y': 'у',
}


def _command_word_spans(payload: str, shell: Shell) -> list[tuple[int, int]]:
    if shell == Shell.POWERSHELL:
        toks = lex_ps(payload)
        return [(toks[i].start, toks[i].end) for i in ps_command_words(toks)]
    if shell in POSIX:
        toks = lex_sh(payload)
        return [(toks[i].start, toks[i].end) for i in sh_command_words(toks)]
    m = re.match(r'\s*([^\s&|<>()"]+)', payload)
    return [(m.start(1), m.end(1))] if m else []


def _probe(shell: Shell, kind: str):
    def run(payload: str, rng: random.Random) -> str | None:
        spans = [
            (a, b)
            for a, b in _command_word_spans(payload, shell)
            if b - a >= 2 and payload[a:b].isascii()
        ]
        if not spans:
            return None
        a, b = rng.choice(spans)
        if kind == 'zero_width':
            at = rng.randint(a + 1, b - 1)
            return payload[:at] + rng.choice(ZERO_WIDTH) + payload[at:]
        word = payload[a:b]
        spots = [k for k, c in enumerate(word) if c.lower() in HOMOGLYPHS]
        if kind == 'fullwidth' or not spots:
            new = ''.join(
                chr(ord(c) + 0xFEE0) if '!' <= c <= '~' else c for c in word
            )
        else:
            k = rng.choice(spots)
            new = word[:k] + HOMOGLYPHS[word[k].lower()] + word[k + 1 :]
        return payload[:a] + new + payload[b:]

    return run


for _shell in Shell:
    for _kind in ('zero_width', 'homoglyph', 'fullwidth'):
        register(f'common.{_kind}', {_shell}, semantic=False)(
            _probe(_shell, _kind)
        )


# --- line splitting ---


def _split_lines(shell: Shell):
    def run(payload: str, rng: random.Random) -> str | None:
        if shell == Shell.CMD:
            if '%' in payload or '!' in payload or '\n' in payload.strip():
                return None
            if cmd_has_unquoted(payload, '|') or _cmd_last_is_set(payload):
                return None
            mask = cmd_quote_mask(payload)
            spots = [
                i
                for i, ch in enumerate(payload)
                if ch == ' '
                and mask[i]
                and i + 1 < len(payload)
                and (payload[i + 1].isalnum() or payload[i + 1] in '/-.')
                and not payload[:i].lower().lstrip().startswith('set')
            ]
            cont = ' ^\n'
        else:
            toks = (
                lex_ps(payload)
                if shell == Shell.POWERSHELL
                else lex_sh(payload)
            )
            spots = [
                t.start
                for k, t in enumerate(toks)
                if t.kind == 'ws'
                and t.text == ' '
                and 0 < k < len(toks) - 1
                and toks[k + 1].kind not in ('comment', 'nl')
                and toks[k - 1].kind != 'nl'
            ]
            cont = ' `\n' if shell == Shell.POWERSHELL else ' \\\n'
        if not spots:
            return None
        picks = rng.sample(spots, k=min(len(spots), rng.randint(1, 3)))
        for i in sorted(picks, reverse=True):
            payload = payload[:i] + cont + payload[i + 1 :]
        return payload

    return run


for _shell in (Shell.CMD, Shell.POWERSHELL, Shell.SH, Shell.BASH, Shell.ZSH):
    register('common.newline_split', {_shell})(_split_lines(_shell))
