"""Find scripts nested inside a payload (S8 §1-§2, phase-5.md §5.3.5).

Parsers never look inside strings, so ``powershell -EncodedCommand <b64>``,
``powershell -c "..."``, ``cmd /c "..."``, ``bash -c '...'``, ``sh -c``,
``zsh -c``, ``eval "..."`` and ``iex '...'`` hide whole scripts. This module
extracts them (pure functions, no IO); ``Validator`` validates each one
recursively, at most ``RECURSE_MAX_DEPTH`` levels deep.
"""

from __future__ import annotations

import base64
import binascii
import re
import shlex
from dataclasses import dataclass

from redteam.models import Shell

from . import cmd_tokenizer

# Same limit as the core's deobfuscation depth (CLAUDE.md, S8 §1).
RECURSE_MAX_DEPTH = 5
# Inner scripts taken per level; more is reported, never silently dropped.
RECURSE_MAX_INNER = 16
# Decoded -EncodedCommand text is capped like any payload.
RECURSE_MAX_DECODED_CHARS = 256 * 1024


@dataclass(frozen=True)
class Inner:
    shell: Shell
    src: str = ''
    # Set when the nested script could not be extracted (bad base64 ...).
    error: str | None = None

    def __repr__(self) -> str:  # never show the script text
        return f'Inner(shell={self.shell.value!r}, error={self.error!r})'


_PS_NAMES = ('powershell', 'pwsh')
_POSIX_NAMES = {'bash': Shell.BASH, 'sh': Shell.SH, 'dash': Shell.SH}
_POSIX_NAMES['zsh'] = Shell.ZSH
# pwsh/powershell parameters that take a value (prefix-matched).
_PS_VALUE_PARAMS = (
    'windowstyle',
    'executionpolicy',
    'ep',
    'inputformat',
    'outputformat',
    'configurationname',
    'workingdirectory',
    'wd',
    'settingsfile',
    'custompipename',
    'version',
    'psconsolefile',
)
_PS_FLAG_PARAMS = (
    'noprofile',
    'nop',
    'noninteractive',
    'noni',
    'nologo',
    'noexit',
    'sta',
    'mta',
    'login',
    'l',
    'interactive',
    'i',
)


def _unquote(word: str) -> str:
    if len(word) >= 2 and word[0] == word[-1] and word[0] in '"\'':
        return word[1:-1]
    return word


def _ps_param(arg: str) -> str | None:
    if len(arg) >= 2 and arg[0] in '-/' and arg[1] != '-':
        return arg[1:].lower()
    if arg.startswith('--') and len(arg) > 2:
        return arg[2:].lower()
    return None


def _is_prefix(name: str, full: str, minimum: int = 1) -> bool:
    return len(name) >= minimum and full.startswith(name)


def decode_encoded_command(value: str) -> str | None:
    """Base64 -> UTF-16LE, as ``powershell -EncodedCommand`` does."""
    value = _unquote(value.strip())
    if len(value) > RECURSE_MAX_DECODED_CHARS * 3:
        return None
    try:
        raw = base64.b64decode(value, validate=True)
        text = raw.decode('utf-16-le')
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    return text


def _from_powershell(args: list[str], name: str) -> list[Inner]:
    i = 0
    while i < len(args):
        arg = args[i]
        param = _ps_param(arg)
        if param is None:
            # Windows PowerShell treats a bare argument as -Command; pwsh 7
            # treats it as -File (nothing to parse here).
            if name == 'powershell':
                text = ' '.join(_unquote(a) for a in args[i:])
                return [Inner(Shell.POWERSHELL, text)]
            return []
        if param in ('ec', 'e') or _is_prefix(param, 'encodedcommand', 2):
            if i + 1 >= len(args):
                return [Inner(Shell.POWERSHELL, error='recurse.missing-value')]
            text = decode_encoded_command(args[i + 1])
            if text is None:
                return [Inner(Shell.POWERSHELL, error='recurse.bad-base64')]
            return [Inner(Shell.POWERSHELL, text)]
        if _is_prefix(param, 'command'):
            rest = args[i + 1 :]
            if not rest or rest == ['-']:
                return []
            if len(rest) == 1:
                return [Inner(Shell.POWERSHELL, _unquote(rest[0]))]
            return [
                Inner(Shell.POWERSHELL, ' '.join(_unquote(a) for a in rest))
            ]
        if _is_prefix(param, 'file') or param == 'f':
            return []
        if any(_is_prefix(param, p) for p in _PS_FLAG_PARAMS) and not any(
            p == param for p in _PS_VALUE_PARAMS
        ):
            i += 1
            continue
        # Value-taking parameter (or unknown one): skip its value.
        i += 2
    return []


def _from_cmd(glued: str, args: list[str]) -> list[Inner]:
    """``cmd [/q /d /v:on ...] /c|/k <command line>``."""
    all_args = ([glued] if glued else []) + args
    for i, arg in enumerate(all_args):
        if not arg.startswith('/'):
            return []
        options = [o.lower() for o in arg.split('/') if o]
        if any(o in ('c', 'k') for o in options):
            text = ' '.join(all_args[i + 1 :])
            if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
                text = text[1:-1]
            return [Inner(Shell.CMD, text)] if text.strip() else []
    return []


def _from_posix(shell: Shell, args: list[str]) -> list[Inner]:
    for i, arg in enumerate(args):
        if arg.startswith('-') and not arg.startswith('--'):
            if 'c' in arg[1:] and arg[1:].isalpha():
                if i + 1 < len(args):
                    return [Inner(shell, _unquote(args[i + 1]))]
                return [Inner(shell, error='recurse.missing-value')]
            continue
        if arg.startswith('--'):
            continue
        return []  # a script file: nothing inline
    return []


_CMD_GLUED = re.compile(r'(?i)(?:.*\\)?cmd(?:\.exe)?((?:/[^/\s]+)+)')


def from_argv(argv: list[str], outer: Shell) -> list[Inner]:
    """Inner scripts carried by one command line (argv[0] = program)."""
    if not argv:
        return []
    raw0 = _unquote(argv[0])
    args = argv[1:]
    glued = _CMD_GLUED.fullmatch(raw0)
    if glued:
        return _from_cmd(glued.group(1), args)
    base = re.split(r'[\\/]', raw0)[-1].lower()
    name = base[:-4] if base.endswith('.exe') else base
    if name in _PS_NAMES:
        return _from_powershell(args, name)
    if name == 'cmd':
        return _from_cmd('', args)
    if name in _POSIX_NAMES:
        return _from_posix(_POSIX_NAMES[name], args)
    if name == 'eval' and outer in (Shell.BASH, Shell.SH, Shell.ZSH):
        if args:
            return [Inner(outer, ' '.join(_unquote(a) for a in args))]
        return []
    if name in ('iex', 'invoke-expression') and outer is Shell.POWERSHELL:
        if args and args[0][:1] in '"\'':
            return [Inner(Shell.POWERSHELL, _unquote(args[0]))]
        return []
    return []


# --------------------------------------------------------------------------
# Splitting the outer payload into command lines

_LAUNCHER = re.compile(
    r'(?i)(?:^|(?<=[\s;|&({`\'"]))'
    r'((?:[\w.:~$-]*[\\/])?(?:powershell|pwsh|cmd|bash|zsh|dash|sh)'
    r'(?:\.exe)?(?:/[a-z:/]*)?|eval|iex|invoke-expression)(?=[\s(\'"]|$)'
)


def _posix_words(text: str) -> list[str]:
    """Shell words up to the end of the simple command (best effort)."""
    lex = shlex.shlex(text, posix=True, punctuation_chars=';&|()<>')
    lex.whitespace_split = True
    lex.commenters = ''
    words: list[str] = []
    try:
        while len(words) < 64:
            tok = lex.get_token()
            if tok is None or tok == lex.eof:
                break
            if tok and set(tok) <= set(';&|()<>'):
                break
            words.append(tok)
    except ValueError:
        pass  # unbalanced quote: keep what we have
    return words


def _ps_words(text: str) -> list[str]:
    """PowerShell-ish words up to a statement end; quotes are kept."""
    words: list[str] = []
    i, n = 0, len(text)
    while i < n and len(words) < 64:
        while i < n and text[i] in ' \t':
            i += 1
        if i >= n or text[i] in ';|\n}':
            break
        if text[i] == '&' and (i + 1 < n and text[i + 1] == '&'):
            break
        start = i
        if text[i] in '\'"':
            q = text[i]
            i += 1
            while i < n:
                if text[i] == '`' and q == '"' and i + 1 < n:
                    i += 2
                    continue
                if text[i] == q:
                    if i + 1 < n and text[i + 1] == q:
                        i += 2
                        continue
                    i += 1
                    break
                i += 1
            word = text[start:i]
            body = word[1:-1] if len(word) >= 2 else word[1:]
            body = body.replace(q * 2, q)
            if q == '"':
                body = re.sub(r'`(.)', r'\1', body)
            words.append(q + body + q)
            continue
        while i < n and text[i] not in ' \t;|\n}':
            i += 1
        words.append(text[start:i])
    return words


def find_inner(src: str, shell: Shell) -> list[Inner]:
    """All directly nested scripts in ``src`` (one level)."""
    found: list[Inner] = []
    if shell is Shell.CMD:
        for command in cmd_tokenizer.parse(src).commands:
            found.extend(from_argv(list(command.words), shell))
        return found
    if shell is Shell.APPLESCRIPT:
        return found
    words_of = _ps_words if shell is Shell.POWERSHELL else _posix_words
    for m in _LAUNCHER.finditer(src):
        argv = words_of(src[m.start(1) :])
        if not argv:
            continue
        found.extend(from_argv(argv, shell))
    return found
