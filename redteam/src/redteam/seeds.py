"""Seeds: the malicious ``command.analyze`` corpus cases (phase-5.md §5.2).

Payloads are assembled from the corpus ``Text`` forms at runtime and live in
memory only. The train / heldout split depends on ``sha256(case id)`` alone, so
it never changes between versions or runs.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from redteam.models import Seed, Shell, Split

HELDOUT_RATIO = 0.2

# Mirrors paste-warden-corpus MAX_TEXT_CHARS (crates/corpus/src/lib.rs).
MAX_TEXT_CHARS = 8 << 20

REPO_ROOT = Path(__file__).resolve().parents[3]
CORPUS_DIR = REPO_ROOT / 'corpus'


class TextError(ValueError):
    """A corpus Text value that cannot be resolved."""


# --- corpus Text -----------------------------------------------------------

_UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
_LOWER = 'abcdefghijklmnopqrstuvwxyz'
_DIGITS = '0123456789'
_CHARSETS = {
    'hex': '0123456789abcdef',
    'HEX': '0123456789ABCDEF',
    'alnum': _UPPER + _LOWER + _DIGITS,
    'lower': _LOWER + _DIGITS,
    'upper': _UPPER + _DIGITS,
    'digits': _DIGITS,
    'base64': _UPPER + _LOWER + _DIGITS + '+/',
    'base64url': _UPPER + _LOWER + _DIGITS + '-_',
}


def charset(name: str) -> str:
    if name in _CHARSETS:
        return _CHARSETS[name]
    if len(name) >= 2:
        return name
    raise TextError(f'unknown charset {name!r}')


def rand_string(seed: int, chars: str, length: int, skip: int = 0) -> str:
    """corpus/README.md §2: the legacy 31-bit LCG, same as the Rust side."""
    state = seed & 0xFFFFFFFF
    out = []
    for i in range(skip + length):
        state = (state * 1103515245 + 12345) & 0x7FFFFFFF
        if i >= skip:
            out.append(chars[(state >> 8) % len(chars)])
    return ''.join(out)


def resolve_text(value: object) -> str:
    """Resolve a corpus Text (string, ``parts``, ``rand``, ``repeat``)."""
    out: list[str] = []
    _resolve_into(value, out)
    return ''.join(out)


def _resolve_into(value: object, out: list[str]) -> None:
    if isinstance(value, str):
        out.append(value)
        return
    if not isinstance(value, dict) or len(value) != 1:
        raise TextError('not a Text value')
    ((key, body),) = value.items()
    if key == 'parts':
        if not isinstance(body, list):
            raise TextError('`parts` must be an array')
        for part in body:
            _resolve_into(part, out)
    elif key == 'rand':
        seed = body.get('seed')
        if not isinstance(seed, int) or not 0 <= seed <= 0xFFFFFFFF:
            raise TextError('rand.seed must fit in u32')
        length = int(body['len'])
        if length > MAX_TEXT_CHARS:
            raise TextError('rand.len too large')
        out.append(
            rand_string(
                seed, charset(body['charset']), length, int(body.get('skip', 0))
            )
        )
    elif key == 'repeat':
        unit = resolve_text(body['text'])
        count = int(body['count'])
        if len(unit) * count > MAX_TEXT_CHARS:
            raise TextError('repeat too large')
        out.append(unit * count)
    else:
        raise TextError(f'not a Text object: {key}')


# --- shell inference -------------------------------------------------------

# Program names are split so this file never holds a whole command keyword.
_PS_EXE = ('power' + 'shell', 'pw' + 'sh')
_CMD_FIRST = {
    'cmd',
    'set',
    'call',
    'start',
    'explorer',
    'ms' + 'hta',
    'cert' + 'util',
    'msi' + 'exec',
    'run' + 'dll32',
    'reg' + 'svr32',
    'bits' + 'admin',
    'w' + 'script',
    'c' + 'script',
}
_PS_FIRST = {
    'i' + 'ex',
    'i' + 'rm',
    'i' + 'wr',
    'saps',
    'invoke-' + 'expression',
    'invoke-' + 'webrequest',
    'invoke-' + 'restmethod',
    'invoke-command',
    'start-process',
    'start-bitstransfer',
    'new-object',
}
_PS_MARKERS = re.compile(
    r'\$env:|\$executioncontext|\[scriptblock\]|\[convert\]|'
    r'\[text\.encoding\]|-outfile\b|\binvoke-|\bnew-object\b|'
    r'\bstart-process\b|\|\s*i' + r'ex\b|^\s*\$\w+\s*=',
    re.IGNORECASE | re.MULTILINE,
)
_CMD_MARKERS = re.compile(
    r'%[A-Za-z_]\w*(:~[^%]*)?%|\^|\|\s*cmd\b', re.IGNORECASE
)
_APPLESCRIPT_START = re.compile(
    r'^\s*(tell\s+application|do\s+shell\s+script|display\s+dialog)\b',
    re.IGNORECASE,
)
_FENCE = re.compile(r'^`{1,3}[a-z]*\s*', re.IGNORECASE)


def _clean_for_inference(payload: str) -> str:
    text = unicodedata.normalize('NFKC', payload)
    text = ''.join(
        ch
        for ch in text
        if unicodedata.category(ch) not in ('Cf', 'Mn') and ch not in 'ᅠㅤﾠ'
    )
    return _FENCE.sub('', text.lstrip())


def _first_word(text: str) -> str:
    text = text.lstrip('&( \t')
    word = re.split(r'[\s(|;&]', text, maxsplit=1)[0]
    for ch in '^`"\'':
        word = word.replace(ch, '')
    word = word.rsplit('\\', 1)[-1].rsplit('/', 1)[-1].lower()
    return word.removesuffix('.exe')


def _posix_flavour(text: str) -> Shell:
    lowered = text.lower()
    if re.search(r'\bzsh\b', lowered):
        return Shell.ZSH
    if re.search(r'\bbash\b|<\(|>&\s*/dev/tcp', lowered):
        return Shell.BASH
    return Shell.SH


def infer_shell(payload: str) -> Shell:
    """Best-effort guess of the shell a payload is meant to be pasted into.

    The first word decides when it names a known program; otherwise markers
    (PowerShell cmdlets and ``$env:``, cmd ``%VAR%`` and ``^``) decide, and
    anything left is POSIX (``bash``/``zsh`` when those are mentioned).
    """
    text = _clean_for_inference(payload)
    if _APPLESCRIPT_START.match(text):
        return Shell.APPLESCRIPT
    first = _first_word(text)
    if first in _PS_EXE or first in _PS_FIRST:
        return Shell.POWERSHELL
    if first in _CMD_FIRST or first.startswith('%') or text.startswith('\\\\'):
        return Shell.CMD
    if first in ('curl', 'wget') and (
        _CMD_MARKERS.search(text)
        or re.search(r'\|\s*(' + '|'.join(_PS_EXE) + r')\b', text, re.I)
        or re.search(r'\.exe\b', text, re.I)
    ):
        return Shell.CMD
    if first in ('bash', 'zsh', 'sh'):
        return {'bash': Shell.BASH, 'zsh': Shell.ZSH}.get(first, Shell.SH)
    if text.startswith(('$', '[', '&', '(')) or _PS_MARKERS.search(text):
        return Shell.POWERSHELL
    if _CMD_MARKERS.search(text):
        return Shell.CMD
    words = set(re.findall(r'[\w.-]+', text.lower()))
    words |= {w.removesuffix('.exe') for w in words}
    if words & set(_PS_EXE):
        return Shell.POWERSHELL
    if words & (_CMD_FIRST - {'set', 'call', 'start'}):
        return Shell.CMD
    return _posix_flavour(text)


# --- split -----------------------------------------------------------------


def split_for(case_id: str, ratio: float = HELDOUT_RATIO) -> Split:
    """Stable split: the first 8 bytes of sha256(id) as a fraction."""
    digest = hashlib.sha256(case_id.encode('utf-8')).digest()
    fraction = int.from_bytes(digest[:8], 'big') / 2**64
    return 'heldout' if fraction < ratio else 'train'


# --- loading ---------------------------------------------------------------


@dataclass
class SeedStats:
    total: int = 0
    skipped: Counter[str] = field(default_factory=Counter)
    per_shell: Counter[str] = field(default_factory=Counter)
    per_split: Counter[str] = field(default_factory=Counter)

    def as_dict(self) -> dict[str, object]:
        return {
            'total': self.total,
            'skipped': dict(self.skipped),
            'per_shell': dict(sorted(self.per_shell.items())),
            'per_split': dict(sorted(self.per_split.items())),
        }


def _case_lines(cases_dir: Path) -> Iterable[dict]:
    for path in sorted(cases_dir.glob('*.jsonl')):
        for line in path.read_text(encoding='utf-8').splitlines():
            if line.strip():
                yield json.loads(line)


def is_seed_case(case: dict) -> bool:
    """Malicious ``command.analyze`` cases. Cases the blue team added from a
    run (``source: redteam:...``) are not seeds, so the seed set and its
    split stay fixed across rounds."""
    return (
        case.get('op') == 'command.analyze'
        and isinstance(case.get('expect'), dict)
        and case['expect'].get('level') == 'malicious'
        and not str(case.get('source', '')).startswith('redteam:')
    )


def load_seeds(
    corpus_dir: Path = CORPUS_DIR, stats: SeedStats | None = None
) -> list[Seed]:
    """All malicious ``command.analyze`` cases, sorted by id.

    ``rand`` is resolved exactly like the Rust side; a case whose Text cannot
    be resolved is skipped and counted in ``stats.skipped``.
    """
    stats = stats if stats is not None else SeedStats()
    seeds = []
    for case in _case_lines(corpus_dir / 'cases'):
        if not is_seed_case(case):
            continue
        try:
            payload = resolve_text(case.get('input'))
        except (TextError, KeyError, TypeError, ValueError):
            stats.skipped['unresolvable_text'] += 1
            continue
        if not payload.strip():
            stats.skipped['empty'] += 1
            continue
        seed = Seed(
            case_id=case['id'],
            shell=infer_shell(payload),
            split=split_for(case['id']),
            payload=payload,
        )
        seeds.append(seed)
        stats.total += 1
        stats.per_shell[seed.shell.value] += 1
        stats.per_split[seed.split] += 1
    seeds.sort(key=lambda s: s.case_id)
    return seeds


def train(seeds: Iterable[Seed]) -> list[Seed]:
    return [s for s in seeds if s.split == 'train']


def heldout(seeds: Iterable[Seed]) -> list[Seed]:
    return [s for s in seeds if s.split == 'heldout']
