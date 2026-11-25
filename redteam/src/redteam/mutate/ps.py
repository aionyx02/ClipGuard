"""G0 mutators for PowerShell (phase-5.md §5.3.2).

A payload is either a script typed at a PowerShell prompt, or a launcher
(``<ps> -w hidden -c "<script>"``). Script rewrites apply to the whole
payload or, for a launcher, to the inner script, which is unquoted, rewritten
and quoted again for the outer string. Only string literals, command-position
words and parameters are touched; anything unclear returns ``None``.
"""

from __future__ import annotations

import base64
import random
import re
from collections.abc import Callable

from redteam.models import Shell

from . import _kw
from .lex import (
    PS_ESCAPE_LETTERS,
    Tok,
    is_ps_command_name,
    lex_ps,
    ps_command_words,
    sq_quote,
    sq_value,
)
from .registry import register

PS = frozenset({Shell.POWERSHELL})

ScriptFn = Callable[[str, random.Random, 'Ctx'], str | None]


class Ctx:
    """What a script rewrite may assume about its host."""

    def __init__(self, windows_ps: bool) -> None:
        # True only inside a Windows PowerShell 5.1 launcher, where the
        # ``curl``/``wget`` aliases of Invoke-WebRequest exist.
        self.windows_ps = windows_ps


# --- launcher ----------------------------------------------------------------


class Launcher:
    def __init__(self, toks: list[Tok], exe_idx: int, arg_idx: int, exe: str):
        self.toks = toks
        self.exe_idx = exe_idx
        self.arg_idx = arg_idx  # the token holding the script
        self.exe = exe


def _exe_name(word: str) -> str:
    name = word.replace('`', '').rsplit('\\', 1)[-1].rsplit('/', 1)[-1]
    return name.lower().removesuffix('.exe')


def _is_command_param(word: str) -> bool:
    # `-co` is ambiguous in PowerShell 7 (-ConfigurationName), so only
    # `-c` and prefixes from `-com` on count.
    w = word.lower()
    return w == '-c' or (len(w) >= 4 and '-command'.startswith(w))


def find_launcher(text: str) -> Launcher | None:
    toks = lex_ps(text)
    words = ps_command_words(toks)
    if not words:
        return None
    exe_idx = words[0]
    # `& "C:\...\ps.exe"` style launchers are left alone.
    exe = _exe_name(toks[exe_idx].text)
    if exe not in _kw.PS_EXES:
        return None
    i = exe_idx + 1
    while i < len(toks):
        t = toks[i]
        if t.kind in ('nl', 'comment') or (t.kind == 'op' and t.text in '|;&'):
            return None
        if t.kind == 'word' and _is_command_param(t.text):
            j = i + 1
            while j < len(toks) and toks[j].kind == 'ws':
                j += 1
            if j < len(toks) and toks[j].kind in ('dq', 'sq'):
                return Launcher(toks, exe_idx, j, exe)
            return None
        i += 1
    return None


def _inner_script(text: str, la: Launcher) -> str | None:
    tok = la.toks[la.arg_idx]
    if tok.kind == 'sq':
        return sq_value(tok.text)
    body = tok.text[1:-1]
    if any(c in body for c in '$`"'):
        return None
    return body


def _requote(la: Launcher, script: str) -> str | None:
    if '"' in script:
        # Windows PowerShell passes embedded quotes to native programs
        # unescaped; keep away from that.
        return None
    if la.toks[la.arg_idx].kind == 'sq':
        return sq_quote(script)
    return '"' + script.replace('`', '``').replace('$', '`$') + '"'


def map_script(payload: str, rng: random.Random, fn: ScriptFn) -> str | None:
    """Apply ``fn`` to the payload as a script, or to a launcher's script."""
    targets = ['outer']
    la = None
    try:
        la = find_launcher(payload)
    except ValueError:
        la = None
    if la is not None:
        targets.append('inner')
    rng.shuffle(targets)
    for target in targets:
        if target == 'outer':
            out = fn(payload, rng, Ctx(windows_ps=False))
            if out is not None:
                return out
            continue
        inner = _inner_script(payload, la)
        if inner is None:
            continue
        new_inner = fn(inner, rng, Ctx(windows_ps=la.exe == _kw.PS))
        if new_inner is None:
            continue
        quoted = _requote(la, new_inner)
        if quoted is None:
            continue
        tok = la.toks[la.arg_idx]
        return payload[: tok.start] + quoted + payload[tok.end :]
    return None


def script_mutator(technique: str) -> Callable[[ScriptFn], ScriptFn]:
    def deco(fn: ScriptFn) -> ScriptFn:
        def run(payload: str, rng: random.Random) -> str | None:
            return map_script(payload, rng, fn)

        run.__name__ = fn.__name__
        run.__doc__ = fn.__doc__
        register(technique, PS)(run)
        return fn

    return deco


# --- string sites ------------------------------------------------------------

_URL_WORD = re.compile(r'https?://[A-Za-z0-9._~:/%?-]+')


def string_sites(text: str) -> list[tuple[int, int, str]]:
    """(start, end, value) of string literals that may become expressions.

    Single-quoted strings standing alone, and URL barewords in argument
    position (``irm https://x`` is the string ``'https://x'``).
    """
    toks = lex_ps(text)
    cmd_words = set(ps_command_words(toks))
    sites = []
    for idx, t in enumerate(toks):
        prev = toks[idx - 1] if idx else None
        nxt = toks[idx + 1] if idx + 1 < len(toks) else None
        if prev is not None and prev.kind in ('word', 'var', 'sq', 'dq'):
            continue
        if t.kind == 'sq':
            if prev is not None and prev.kind == 'op' and prev.text == '[':
                continue
            sites.append((t.start, t.end, sq_value(t.text)))
        elif (
            t.kind == 'word'
            and idx not in cmd_words
            and _URL_WORD.fullmatch(t.text)
            and (prev is None or prev.kind == 'ws')
            and (
                nxt is None
                or nxt.kind in ('ws', 'nl', 'comment')
                or (nxt.kind == 'op' and nxt.text in '|;)')
            )
        ):
            sites.append((t.start, t.end, t.text))
    return sites


def _replace_site(
    text: str, rng: random.Random, build: Callable[[str, random.Random], str]
) -> str | None:
    sites = [s for s in string_sites(text) if len(s[2]) >= 2]
    if not sites:
        return None
    start, end, value = rng.choice(sites)
    return text[:start] + build(value, rng) + text[end:]


def _cut(value: str, rng: random.Random, pieces: int) -> list[str]:
    pieces = max(2, min(pieces, len(value)))
    cuts = sorted(rng.sample(range(1, len(value)), k=pieces - 1))
    bounds = [0, *cuts, len(value)]
    return [value[a:b] for a, b in zip(bounds, bounds[1:], strict=False)]


@script_mutator('ps.concat')
def concat(text: str, rng: random.Random, ctx: Ctx) -> str | None:
    """``'abc'`` -> ``('ab'+'c')``."""

    def build(value: str, rng: random.Random) -> str:
        parts = _cut(value, rng, rng.randint(2, 4))
        return '(' + '+'.join(sq_quote(p) for p in parts) + ')'

    return _replace_site(text, rng, build)


@script_mutator('ps.format')
def format_op(text: str, rng: random.Random, ctx: Ctx) -> str | None:
    """``'abc'`` -> ``('{1}{0}' -f 'c','ab')``."""

    def build(value: str, rng: random.Random) -> str:
        parts = _cut(value, rng, rng.randint(2, 4))
        order = list(range(len(parts)))
        rng.shuffle(order)
        # Slot k of the argument list holds part order[k].
        slot_of = {part: k for k, part in enumerate(order)}
        fmt = ''.join(f'{{{slot_of[p]}}}' for p in range(len(parts)))
        args = ','.join(sq_quote(parts[p]) for p in order)
        return f"('{fmt}' -f {args})"

    return _replace_site(text, rng, build)


@script_mutator('ps.char')
def char_codes(text: str, rng: random.Random, ctx: Ctx) -> str | None:
    """``'ab'`` -> ``(-join [char[]](97,98))``."""

    def build(value: str, rng: random.Random) -> str:
        codes = ','.join(str(ord(c)) for c in value)
        return f'(-join [char[]]({codes}))'

    sites = [
        s for s in string_sites(text) if all(ord(c) <= 0xFFFF for c in s[2])
    ]
    if not sites or not any(len(s[2]) >= 2 for s in sites):
        return None
    return _replace_site(text, rng, build)


@script_mutator('ps.reverse')
def reverse(text: str, rng: random.Random, ctx: Ctx) -> str | None:
    """``'abc'`` -> ``(-join ('cba'[-1..-3]))``."""

    def build(value: str, rng: random.Random) -> str:
        rev = sq_quote(value[::-1])
        return f'(-join ({rev}[-1..-{len(value)}]))'

    sites = [
        s for s in string_sites(text) if all(ord(c) <= 0xFFFF for c in s[2])
    ]
    if not any(len(s[2]) >= 2 for s in sites):
        return None
    return _replace_site(text, rng, build)


# --- command words ------------------------------------------------------------


def _command_word_toks(text: str) -> list[Tok]:
    toks = lex_ps(text)
    return [
        toks[i]
        for i in ps_command_words(toks)
        if is_ps_command_name(toks[i].text)
    ]


@script_mutator('ps.backtick')
def backtick(text: str, rng: random.Random, ctx: Ctx) -> str | None:
    """`` `` `` before ordinary letters of a command name or inside a
    ``"..."`` string without ``$``: PowerShell drops the backtick."""
    toks = lex_ps(text)
    spots = []
    for t in _command_word_toks(text):
        spots += [
            t.start + k
            for k in range(1, len(t.text))
            if t.text[k].isalpha() and t.text[k] not in PS_ESCAPE_LETTERS
        ]
    for t in toks:
        if t.kind == 'dq' and '$' not in t.text and '`' not in t.text:
            spots += [
                t.start + k
                for k in range(1, len(t.text) - 1)
                if t.text[k].isascii()
                and t.text[k].isalpha()
                and t.text[k] not in PS_ESCAPE_LETTERS
            ]
    if not spots:
        return None
    picks = rng.sample(spots, k=min(len(spots), rng.randint(1, 4)))
    for i in sorted(picks, reverse=True):
        text = text[:i] + '`' + text[i:]
    return text


ALIASES: list[tuple[str, ...]] = [
    (_kw.IWR, _kw.INVOKE_WEBREQUEST),
    (_kw.IRM, _kw.INVOKE_RESTMETHOD),
    (_kw.IEX, _kw.INVOKE_EXPRESSION),
    (_kw.SAPS, 'start', _kw.START_PROCESS),
    (_kw.ICM, _kw.INVOKE_COMMAND),
]
# Windows PowerShell 5.1 only (removed in PowerShell 7).
WINDOWS_PS_ALIASES = {_kw.INVOKE_WEBREQUEST.lower(): ('curl', 'wget')}


@script_mutator('ps.alias')
def alias(text: str, rng: random.Random, ctx: Ctx) -> str | None:
    """``iwr`` <-> ``Invoke-WebRequest`` (and ``curl`` on 5.1), ..."""
    choices = []
    for t in _command_word_toks(text):
        for group in ALIASES:
            names = [g.lower() for g in group]
            if t.text.lower() in names:
                alts = [g for g in group if g.lower() != t.text.lower()]
                if ctx.windows_ps:
                    alts += WINDOWS_PS_ALIASES.get(group[-1].lower(), ())
                choices.append((t, alts))
    if not choices:
        return None
    t, alts = rng.choice(choices)
    return text[: t.start] + rng.choice(alts) + text[t.end :]


def _var_name(text: str, rng: random.Random) -> str | None:
    name = 'pw' + ''.join(rng.choice('abcdefghjkmnpqrstuvwxyz') for _ in '12')
    if ('$' + name).lower() in text.lower():
        return None
    return name


@script_mutator('ps.var_indirection')
def var_indirection(text: str, rng: random.Random, ctx: Ctx) -> str | None:
    """``iex x`` -> ``$v='i'+'ex';& $v x``."""
    words = _command_word_toks(text)
    lead = text.lstrip()
    if not words or lead.lower().startswith(('param', 'using', '#requires')):
        return None
    t = rng.choice(words)
    name = _var_name(text, rng)
    if name is None:
        return None
    value = t.text
    if len(value) >= 2:
        parts = _cut(value, rng, 2)
        expr = '+'.join(sq_quote(p) for p in parts)
    else:
        expr = sq_quote(value)
    after = text[t.end : t.end + 1]
    call = f'& ${name}' + ('' if after in ('', ' ', '\t', '\n') else ' ')
    body = text[: t.start] + call + text[t.end :]
    return f'${name}={expr};{body}'


PS_OPERATORS = frozenset(
    '-f -join -split -replace -eq -ne -like -match -as -is -band -bor '
    '-bxor -not -and -or'.split()
)


def _case_insensitive_command(word: str) -> bool:
    if _exe_name(word) in _kw.PS_EXES:
        return True
    if re.fullmatch(r'[a-z]+-[a-z]+', word):
        return True
    return any(word in (g.lower() for g in group) for group in ALIASES)


@script_mutator('ps.case')
def case(text: str, rng: random.Random, ctx: Ctx) -> str | None:
    """Random case for command names, parameters, type and member names."""
    toks = lex_ps(text)
    cmd_words = set(ps_command_words(toks))
    spans = []
    current = ''
    for idx, t in enumerate(toks):
        prev = toks[idx - 1] if idx else None
        if idx in cmd_words:
            current = t.text.lower()
        if t.kind != 'word' or '`' in t.text:
            continue
        is_param = re.fullmatch(r'-[A-Za-z]+', t.text) is not None
        if (
            (idx in cmd_words and is_ps_command_name(t.text))
            or (is_param and t.text.lower() in PS_OPERATORS)
            # Native programs may have case-sensitive flags (curl -s/-S),
            # so parameters only after a cmdlet, an alias or the launcher.
            or (is_param and _case_insensitive_command(current))
            or (prev is not None and prev.kind == 'op' and prev.text == '[')
            or (
                t.text.startswith(('.', '::'))
                and prev is not None
                and prev.kind in ('op', 'var')
                and (prev.kind == 'var' or prev.text in ')]')
            )
        ):
            spans.append(t)
    if not spans:
        return None
    for t in sorted(
        rng.sample(spans, k=min(len(spans), 3)), key=lambda t: -t.start
    ):
        flipped = ''.join(
            c.upper() if rng.random() < 0.5 else c.lower() for c in t.text
        )
        if flipped == t.text:
            flipped = t.text.swapcase()
        text = text[: t.start] + flipped + text[t.end :]
    return text


# --- launcher-level ---

PARAM_CLASSES: list[tuple[str, ...]] = [
    ('-WindowStyle', '-w', '-win', '-windowstyle', '-WindowSt'),
    ('-NoProfile', '-nop', '-noprofile', '-NoP'),
    ('-NonInteractive', '-noni', '-nonint'),
    ('-ExecutionPolicy', '-ep', '-exec', '-ex'),
    ('-Command', '-c', '-command'),
    (_kw.ENCODED_COMMAND, '-e', '-enc', '-ec'),
]
# ``-w h`` is not used: Windows PowerShell parses the value with a plain enum
# conversion, and ``1`` (= Hidden) is the abbreviation that is certain.
WINDOW_VALUES = ('Hidden', 'hidden', '1')
SCRIPT_PARAM_CLASSES: list[tuple[str, ...]] = [
    ('-UseBasicParsing', '-useb', '-UseB'),
    ('-ArgumentList', '-args'),
]


def _find_class(word: str, classes) -> tuple[str, ...] | None:
    for group in classes:
        if word.lower() in (g.lower() for g in group):
            return group
    return None


def _swap_param(word: str, classes, rng) -> str | None:
    group = _find_class(word, classes)
    if group is None:
        return None
    return rng.choice([g for g in group if g.lower() != word.lower()])


@register('ps.param_abbrev', PS)
def param_abbrev(payload: str, rng: random.Random) -> str | None:
    """``-WindowStyle Hidden`` <-> ``-w 1``, ``-NoProfile`` <-> ``-nop``."""
    toks = lex_ps(payload)
    words = ps_command_words(toks)
    choices = []
    launcher = words and _exe_name(toks[words[0]].text) in _kw.PS_EXES
    in_launcher_args = bool(launcher)
    for idx, t in enumerate(toks):
        if t.kind in ('dq', 'sq', 'nl', 'comment'):
            in_launcher_args = False
        if t.kind != 'word' or not t.text.startswith('-'):
            continue
        classes = PARAM_CLASSES if in_launcher_args else SCRIPT_PARAM_CLASSES
        if _find_class(t.text, classes) is not None:
            choices.append((idx, classes))
        if in_launcher_args and t.text.lower() in (
            '-windowstyle',
            '-w',
            '-win',
        ):
            nxt = idx + 2 if idx + 2 < len(toks) else None
            if (
                nxt is not None
                and toks[idx + 1].kind == 'ws'
                and toks[nxt].kind == 'word'
                and toks[nxt].text.lower() in ('hidden', '1')
            ):
                choices.append((nxt, 'value'))
    if not choices:
        return None
    idx, classes = rng.choice(choices)
    t = toks[idx]
    if classes == 'value':
        new = rng.choice([v for v in WINDOW_VALUES if v != t.text])
    else:
        new = _swap_param(t.text, classes, rng)
    return payload[: t.start] + new + payload[t.end :]


def encode_command(script: str) -> str:
    return base64.b64encode(script.encode('utf-16-le')).decode('ascii')


@register('ps.encoded_command', PS)
def encoded_command(payload: str, rng: random.Random) -> str | None:
    """Script -> ``<ps> -NoProfile -enc <UTF-16LE base64>``.

    A launcher keeps its options; only ``-c <script>`` is replaced.
    """
    try:
        la = find_launcher(payload)
    except ValueError:
        la = None
    flag = rng.choice([_kw.ENCODED_COMMAND, '-enc', '-e', '-ec'])
    inner = _inner_script(payload, la) if la is not None else None
    if la is not None and inner is not None:
        # Replace from the -c parameter to the end of the script token.
        param = max(
            i
            for i in range(la.exe_idx, la.arg_idx)
            if la.toks[i].kind == 'word' and _is_command_param(la.toks[i].text)
        )
        start = la.toks[param].start
        end = la.toks[la.arg_idx].end
        return (
            payload[:start] + f'{flag} {encode_command(inner)}' + payload[end:]
        )
    lex_ps(payload)  # refuses unterminated input
    script = payload.strip()
    if not script:
        return None
    exe = rng.choice([_kw.PS, _kw.PS + '.exe', _kw.PWSH])
    return f'{exe} -NoProfile {flag} {encode_command(script)}'
