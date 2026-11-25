"""Small, conservative lexers for the G0 mutators.

They do not parse a shell; they find the places where a rewrite is safe
(unquoted code, command-position words, string literals). Anything they do
not understand makes the mutator return ``None`` instead of guessing.
Every lexer is linear: whitespace runs and plain words are single regex
matches, so a 1 Mi-character padded seed stays cheap.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


class Unterminated(ValueError):
    """An open quote or substitution at the end of the input."""


@dataclass(frozen=True)
class Tok:
    kind: str
    start: int
    end: int
    text: str


def splice(text: str, start: int, end: int, new: str) -> str:
    return text[:start] + new + text[end:]


# --- PowerShell -------------------------------------------------------------

PS_KEYWORDS = frozenset(
    'begin break catch class continue data define do dynamicparam else '
    'elseif end enum exit filter finally for foreach from function hidden '
    'if in inlinescript param process return static switch throw trap try '
    'until using var while workflow parallel sequence'.split()
)
# Letters that start an escape sequence after a backtick (`0 `a `b `e ...).
PS_ESCAPE_LETTERS = frozenset('0abefnrtuvABEFNRTUV')

_PS_WS = re.compile(r'[ \t\f\v ]+')
_PS_WORD = re.compile(r'(?:`.|[^\s\'"$|;&(){}\[\],=#<>`+@])+', re.DOTALL)
_PS_VAR = re.compile(r'\$(?:\{[^}]*\}|[A-Za-z0-9_?^$]+(?::[A-Za-z0-9_]+)?)')


def lex_ps(text: str) -> list[Tok]:
    """Tokens: ws nl sq dq here comment var word op."""
    toks: list[Tok] = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch in '\r\n':
            j = i + 1
            if ch == '\r' and j < n and text[j] == '\n':
                j += 1
            toks.append(Tok('nl', i, j, text[i:j]))
            i = j
            continue
        m = _PS_WS.match(text, i)
        if m:
            toks.append(Tok('ws', i, m.end(), m.group()))
            i = m.end()
            continue
        if text.startswith(("@'", '@"'), i) and text[i + 2 : i + 3] in (
            '\n',
            '\r',
        ):
            close = '\n' + text[i + 1] + '@'
            j = text.find(close, i + 2)
            if j < 0:
                raise Unterminated('here-string')
            toks.append(Tok('here', i, j + 3, text[i : j + 3]))
            i = j + 3
            continue
        if ch == "'":
            j = i + 1
            while True:
                k = text.find("'", j)
                if k < 0:
                    raise Unterminated('single quote')
                if text[k + 1 : k + 2] == "'":
                    j = k + 2
                    continue
                break
            toks.append(Tok('sq', i, k + 1, text[i : k + 1]))
            i = k + 1
            continue
        if ch == '"':
            j = _ps_dq_end(text, i + 1)
            toks.append(Tok('dq', i, j, text[i:j]))
            i = j
            continue
        if ch == '#' and (not toks or toks[-1].kind in ('ws', 'nl', 'op')):
            j = i
            while j < n and text[j] not in '\r\n':
                j += 1
            toks.append(Tok('comment', i, j, text[i:j]))
            i = j
            continue
        if ch == '$':
            m = _PS_VAR.match(text, i)
            if m:
                toks.append(Tok('var', i, m.end(), m.group()))
                i = m.end()
                continue
            toks.append(Tok('op', i, i + 1, ch))
            i += 1
            continue
        m = _PS_WORD.match(text, i)
        if m:
            toks.append(Tok('word', i, m.end(), m.group()))
            i = m.end()
            continue
        if ch == '`' and i + 1 < n:
            # Line continuation (or an escape we do not model).
            toks.append(Tok('op', i, i + 2, text[i : i + 2]))
            i += 2
            continue
        toks.append(Tok('op', i, i + 1, ch))
        i += 1
    return toks


def _ps_dq_end(text: str, i: int) -> int:
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == '`':
            i += 2
            continue
        if ch == '"':
            if text[i + 1 : i + 2] == '"':
                i += 2
                continue
            return i + 1
        if ch == '$' and text[i + 1 : i + 2] == '(':
            i = _ps_paren_end(text, i + 2)
            continue
        i += 1
    raise Unterminated('double quote')


def _ps_paren_end(text: str, i: int) -> int:
    depth, n = 1, len(text)
    while i < n:
        ch = text[i]
        if ch == "'":
            k = text.find("'", i + 1)
            if k < 0:
                raise Unterminated('single quote')
            i = k + 1
            continue
        if ch == '"':
            i = _ps_dq_end(text, i + 1)
            continue
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    raise Unterminated('subexpression')


_CMD_POS_AFTER = frozenset('|;({&=')


def ps_command_words(toks: list[Tok]) -> list[int]:
    """Indexes of word tokens in command position."""
    out = []
    prev = None
    for idx, t in enumerate(toks):
        if t.kind == 'ws':
            continue
        if t.kind == 'word' and (
            prev is None
            or prev.kind == 'nl'
            or (prev.kind == 'op' and prev.text in _CMD_POS_AFTER)
        ):
            out.append(idx)
        prev = t
    return out


def is_ps_command_name(word: str) -> bool:
    return (
        re.fullmatch(r'[A-Za-z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)?', word)
        is not None
        and word.lower() not in PS_KEYWORDS
    )


def sq_value(tok_text: str) -> str:
    return tok_text[1:-1].replace("''", "'")


def sq_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


# --- POSIX sh / bash / zsh ---------------------------------------------------

SH_KEYWORDS = frozenset(
    'if then else elif fi case esac for select while until do done in '
    'function time coproc { } ! [[ ]] repeat foreach end'.split()
)
_SH_WS = re.compile(r'[ \t]+')
_SH_PLAIN = re.compile(r'[A-Za-z0-9_./:@%+,-]+')
_SH_WORD = re.compile(r'(?:\\.|[^\s\'"`$|&;<>()\\#])+', re.DOTALL)
_SH_OP = re.compile(r'&&|\|\||;;|\|&|>>|<<<|<<|>&|<&|&>|<>|>\||[|&;<>()]')
_SH_PARAM = re.compile(r'\$(?:[A-Za-z_][A-Za-z0-9_]*|[0-9@*#?$!-])')

PLAIN_WORD = _SH_PLAIN


def lex_sh(text: str) -> list[Tok]:
    """Tokens: ws nl sq dq ansi subst backq param comment word op."""
    toks: list[Tok] = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch == '\n':
            toks.append(Tok('nl', i, i + 1, ch))
            i += 1
            continue
        m = _SH_WS.match(text, i)
        if m:
            toks.append(Tok('ws', i, m.end(), m.group()))
            i = m.end()
            continue
        if ch == '#' and (not toks or toks[-1].kind in ('ws', 'nl', 'op')):
            j = text.find('\n', i)
            j = n if j < 0 else j
            toks.append(Tok('comment', i, j, text[i:j]))
            i = j
            continue
        if ch == "'":
            k = text.find("'", i + 1)
            if k < 0:
                raise Unterminated('single quote')
            toks.append(Tok('sq', i, k + 1, text[i : k + 1]))
            i = k + 1
            continue
        if ch == '"':
            j = _sh_dq_end(text, i + 1)
            toks.append(Tok('dq', i, j, text[i:j]))
            i = j
            continue
        if ch == '`':
            j = _sh_backq_end(text, i + 1)
            toks.append(Tok('backq', i, j, text[i:j]))
            i = j
            continue
        if ch == '$':
            nxt = text[i + 1 : i + 2]
            if nxt == "'":
                j = i + 2
                while j < n and text[j] != "'":
                    j += 2 if text[j] == '\\' else 1
                if j >= n:
                    raise Unterminated('ansi-c quote')
                toks.append(Tok('ansi', i, j + 1, text[i : j + 1]))
                i = j + 1
                continue
            if nxt in ('(', '{'):
                j = (
                    _sh_paren_end(text, i + 2)
                    if nxt == '('
                    else _sh_brace_end(text, i + 2)
                )
                toks.append(Tok('subst', i, j, text[i:j]))
                i = j
                continue
            m = _SH_PARAM.match(text, i)
            if m:
                toks.append(Tok('param', i, m.end(), m.group()))
                i = m.end()
                continue
        m = _SH_OP.match(text, i)
        if m:
            toks.append(Tok('op', i, m.end(), m.group()))
            i = m.end()
            continue
        m = _SH_WORD.match(text, i)
        if m:
            toks.append(Tok('word', i, m.end(), m.group()))
            i = m.end()
            continue
        if ch == '\\':
            toks.append(Tok('word', i, min(i + 2, n), text[i : i + 2]))
            i += 2
            continue
        toks.append(Tok('op', i, i + 1, ch))
        i += 1
    return toks


def _sh_dq_end(text: str, i: int) -> int:
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == '\\':
            i += 2
            continue
        if ch == '"':
            return i + 1
        if ch == '$' and text[i + 1 : i + 2] == '(':
            i = _sh_paren_end(text, i + 2)
            continue
        if ch == '`':
            i = _sh_backq_end(text, i + 1)
            continue
        i += 1
    raise Unterminated('double quote')


def _sh_backq_end(text: str, i: int) -> int:
    n = len(text)
    while i < n:
        if text[i] == '\\':
            i += 2
            continue
        if text[i] == '`':
            return i + 1
        i += 1
    raise Unterminated('backquote')


def _sh_brace_end(text: str, i: int) -> int:
    k = text.find('}', i)
    if k < 0:
        raise Unterminated('parameter expansion')
    return k + 1


def _sh_paren_end(text: str, i: int) -> int:
    depth, n = 1, len(text)
    while i < n:
        ch = text[i]
        if ch == '\\':
            i += 2
            continue
        if ch == "'":
            k = text.find("'", i + 1)
            if k < 0:
                raise Unterminated('single quote')
            i = k + 1
            continue
        if ch == '"':
            i = _sh_dq_end(text, i + 1)
            continue
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    raise Unterminated('command substitution')


_SH_CMD_AFTER = frozenset(['|', '||', '&&', '&', ';', '(', '|&'])


def sh_command_words(toks: list[Tok]) -> list[int]:
    out = []
    prev = None
    for idx, t in enumerate(toks):
        if t.kind == 'ws':
            continue
        if t.kind == 'word' and (
            prev is None
            or prev.kind == 'nl'
            or (prev.kind == 'op' and prev.text in _SH_CMD_AFTER)
        ):
            out.append(idx)
        prev = t
    return out


def is_sh_plain(word: str) -> bool:
    return (
        _SH_PLAIN.fullmatch(word) is not None
        and word not in SH_KEYWORDS
        and '=' not in word
    )


# --- cmd.exe ---------------------------------------------------------------

CMD_BUILTINS = frozenset(
    'assoc break call cd chdir cls color copy date del dir echo endlocal '
    'erase exit for ftype goto if md mkdir mklink move path pause popd '
    'prompt pushd rd rem ren rename rmdir set setlocal shift start time '
    'title type ver verify vol'.split()
)


def cmd_quote_mask(text: str) -> bytearray:
    """1 where a character is unquoted code (not a quote, caret or escaped)."""
    mask = bytearray(len(text))
    quoted = False
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch == '"':
            quoted = not quoted
        elif quoted:
            pass
        elif ch == '^':
            i += 2
            continue
        else:
            mask[i] = 1
        i += 1
    if quoted:
        raise Unterminated('double quote')
    return mask


def cmd_has_unquoted(text: str, chars: str) -> bool:
    mask = cmd_quote_mask(text)
    return any(mask[i] and text[i] in chars for i in range(len(text)))


@dataclass(frozen=True)
class CmdWord:
    start: int
    end: int
    text: str


_CMD_FIRST = re.compile(r'[ \t]*(?P<w>[^\s&|<>()]+)')


def cmd_first_word(text: str) -> CmdWord | None:
    m = _CMD_FIRST.match(text)
    if not m:
        return None
    return CmdWord(m.start('w'), m.end('w'), m.group('w'))
