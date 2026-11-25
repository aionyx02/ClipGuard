"""bash -n / sh -n / zsh -n in the sandbox (S8 §2)."""

import time

import pytest
from conftest import require

from redteam.models import Shell
from redteam.validate import sandbox
from redteam.validate.posix import PosixValidator

GOOD = [
    'echo hello',
    'if true; then echo a; fi',
    'for x in a b; do echo "$x"; done',
    'case x in a) echo a;; *) echo b;; esac',
    'f() { echo "$1"; }; f x',
    'x=$(echo a) && echo "${x:-b}"',
    'cat <<EOF\nhello $USER\nEOF\n',
    'echo a | tr a b > /dev/null 2>&1',
]
BAD = [
    'if true; then echo a',
    'echo "abc',
    "echo 'abc",
    'echo hi |',
    'f() {',
    'for x in a b; echo $x; done',
    'echo ok\n)',
    'echo ${a',
]


@pytest.mark.parametrize('shell', [Shell.BASH, Shell.SH, Shell.ZSH])
def test_good_and_bad(shell, shared_validator):
    require(shell)
    for src in GOOD:
        verdict = shared_validator.validate(src, shell)
        assert verdict.status == 'ok', (src, verdict)
    for src in BAD:
        verdict = shared_validator.validate(src, shell)
        assert verdict.status == 'invalid', (src, verdict)
        assert verdict.errors
        assert all(
            e.id.startswith(('bash.', 'sh.', 'zsh.')) for e in verdict.errors
        )


def test_bash_line_numbers(shared_validator):
    require(Shell.BASH)
    verdict = shared_validator.validate('echo a\necho b\n)', Shell.BASH)
    assert verdict.status == 'invalid'
    assert verdict.errors[0].line == 3


def test_command_substitution_checked_on_every_bash(shared_validator):
    """bash 3.2 skips $(...) under -n; the zsh cross-check covers it."""
    require(Shell.BASH)
    if (shared_validator.posix.bash_major() or 0) < 4:
        require(Shell.ZSH)
    verdict = shared_validator.validate('echo $(if true; then)', Shell.BASH)
    assert verdict.status == 'invalid'


def test_errors_never_quote_the_payload(shared_validator):
    require(Shell.BASH)
    sentinel = 'pastewardensentinel'
    verdict = shared_validator.validate(f'echo {sentinel} )', Shell.BASH)
    assert verdict.status == 'invalid'
    assert sentinel not in verdict.model_dump_json()


def test_zsh_dev_zero_is_crash_within_timeout():
    require(Shell.ZSH)
    start = time.monotonic()
    verdict = PosixValidator().parse('echo $(</dev/zero)', Shell.ZSH)
    elapsed = time.monotonic() - start
    assert verdict.status == 'validator_crash'
    # macOS: RSS watchdog; Linux: RLIMIT_AS -> 'out of heap memory'.
    assert verdict.errors[0].id in (
        'zsh.rss-limit',
        'zsh.timeout',
        'zsh.parse-time-io',
    )
    assert elapsed < sandbox.VALIDATOR_TIMEOUT_MS / 1000 + 1.5


def test_zsh_deep_nesting_is_crash_within_timeout():
    require(Shell.ZSH)
    start = time.monotonic()
    verdict = PosixValidator().parse('echo ' + '$(' * 5000, Shell.ZSH)
    elapsed = time.monotonic() - start
    assert verdict.status in ('validator_crash', 'invalid')
    assert elapsed < sandbox.VALIDATOR_TIMEOUT_MS / 1000 + 1.5
    deep = 'echo ' + '$(' * 5000 + ')' * 5000
    start = time.monotonic()
    verdict = PosixValidator().parse(deep, Shell.ZSH)
    assert verdict.status == 'validator_crash' or verdict.status == 'ok'
    assert time.monotonic() - start < sandbox.VALIDATOR_TIMEOUT_MS / 1000 + 1.5


def test_zsh_parse_time_read_never_passes():
    require(Shell.ZSH)
    verdict = PosixValidator().parse(
        'echo $(</nonexistent.invalid/x)', Shell.ZSH
    )
    assert verdict.status == 'validator_crash'
    assert verdict.errors[0].id == 'zsh.parse-time-io'


def test_no_sandbox_refuses(monkeypatch):
    monkeypatch.setattr(sandbox, 'backend', lambda: None)
    v = PosixValidator()
    if not v.bash:
        pytest.skip('bash not installed')
    verdict = v.parse('echo a', Shell.BASH)
    assert verdict.status == 'validator_crash'
    assert verdict.errors[0].id == 'no-sandbox'


def test_missing_binary_is_unchecked():
    v = PosixValidator()
    v.zsh = None
    assert v.parse('echo', Shell.ZSH).status == 'unchecked'
