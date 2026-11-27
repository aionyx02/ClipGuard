"""pwsh parse server: rejection, protocol, restarts (S8 §1)."""

import json

import pytest
from conftest import J, require

from redteam.models import Shell
from redteam.validate import pwsh_server, sandbox
from redteam.validate.pwsh_server import PwshServer, is_unsafe

USING = J('us', 'ing')

UNSAFE = [
    f'{USING} module Foo',
    f'{USING} assembly System.Xml',
    f'{USING.upper()} MODULE Foo',
    f'{USING}   module\t./x.psm1',
    f'{USING}\nmodule Foo',
    f'{USING} `\n  module Foo',
    'u`s`i`n`g module Foo',
    f'{USING} m`odule Foo',
    f'{USING} <# hidden #> assembly x.dll',
    f'{USING} module Foo',
    f'{USING}​ module Foo',
    f'Get-Date\n{USING} module \\\\host.example.invalid\\share\\x.psm1',
    J('Configuration C { Import-', 'DscResource -ModuleName Foo }'),
]
SAFE = [
    f'{USING} namespace System.IO',
    'Write-Output "confusing modules"',
    '$using = 1; $module = 2',
    'Get-Module -ListAvailable',
]


@pytest.mark.parametrize('src', UNSAFE)
def test_unsafe_detected(src):
    assert is_unsafe(src)


@pytest.mark.parametrize('src', SAFE)
def test_safe_not_flagged(src):
    assert not is_unsafe(src)


@pytest.mark.parametrize('src', UNSAFE)
def test_unsafe_rejected_without_starting_pwsh(src, monkeypatch):
    def boom(*a, **k):
        raise AssertionError('pwsh must not be started')

    monkeypatch.setattr(sandbox.Server, 'start', boom)
    monkeypatch.setattr(sandbox.Server, 'request', boom)
    server = PwshServer()
    server.exe = server.exe or '/nonexistent/pwsh'
    verdict = server.parse(src)
    assert verdict.status == 'rejected_unsafe'
    assert not verdict.ok
    assert server.starts == 0 and server.sent == 0


def test_rejected_inside_encoded_command(shared_validator):
    require(Shell.POWERSHELL)
    import base64

    inner = base64.b64encode(f'{USING} module Foo'.encode('utf-16-le'))
    payload = J('power', 'shell -EncodedCommand ', inner.decode())
    verdict = shared_validator.validate(payload, Shell.POWERSHELL)
    assert verdict.status == 'ok'
    assert verdict.inner[0].status == 'rejected_unsafe'
    assert not verdict.ok


@pytest.fixture
def pwsh():
    require(Shell.POWERSHELL)
    with PwshServer() as server:
        yield server


def test_ok_and_invalid(pwsh):
    assert pwsh.parse('Get-Date | Out-Null').status == 'ok'
    verdict = pwsh.parse('if (')
    assert verdict.status == 'invalid'
    assert verdict.errors[0].id.startswith('pwsh.')
    assert verdict.errors[0].line == 1


def test_columns_count_characters_not_utf16(pwsh):
    # U+1F600 is two UTF-16 units; the error after it is at char 8.
    verdict = pwsh.parse('"\U0001f600" + (')
    assert verdict.status == 'invalid'
    assert {e.column for e in verdict.errors} <= {6, 7, 8}


def test_deep_nesting_is_invalid_not_crash(pwsh):
    verdict = pwsh.parse('(' * 20000 + ')' * 20000)
    assert verdict.status == 'invalid'
    assert any('ScriptTooComplicated' in e.id for e in verdict.errors)
    assert pwsh.parse('1').status == 'ok'


def test_restart_every_n(pwsh, monkeypatch):
    monkeypatch.setattr(pwsh_server, 'PWSH_RESTART_EVERY', 3)
    for _ in range(7):
        assert pwsh.parse('1').status == 'ok'
    assert pwsh.starts == 3


def test_crash_then_restart(pwsh):
    assert pwsh.parse('1').status == 'ok'
    pwsh._server._proc.kill()
    pwsh._server._proc.wait()
    # Dead server is noticed before sending: fresh server, item is fine.
    assert pwsh.parse('1').status == 'ok'
    assert pwsh.starts == 2


def test_timeout_is_crash_and_recovers(pwsh):
    assert pwsh.parse('1').status == 'ok'
    pwsh.timeout_ms = 0
    verdict = pwsh.parse('2')
    assert verdict.status == 'validator_crash'
    assert verdict.errors[0].id == 'pwsh.timeout'
    pwsh.timeout_ms = sandbox.VALIDATOR_TIMEOUT_MS
    assert pwsh.parse('3').status == 'ok'
    assert pwsh.starts == 2


@pytest.mark.parametrize(
    'reply',
    [
        b'{"id": 999, "ok": true, "errors": []}',
        b'not json',
        b'{"id": %d, "fatal": "server-exception"}',
        b'{"id": %d, "ok": true, "errors": [{"id": "X"}]}',
        b'{"id": %d, "ok": "yes", "errors": []}',
    ],
)
def test_protocol_errors_are_crashes(pwsh, monkeypatch, reply):
    assert pwsh.parse('1').status == 'ok'

    def fake(self, line, timeout_ms=0):
        req = json.loads(line)
        return reply % req['id'] if b'%d' in reply else reply

    monkeypatch.setattr(sandbox.Server, 'request', fake)
    verdict = pwsh.parse('2')
    assert verdict.status == 'validator_crash'
    assert verdict.errors[0].id == 'pwsh.protocol'


def test_no_sandbox_refuses(monkeypatch):
    monkeypatch.setattr(sandbox, 'backend', lambda: None)
    server = PwshServer()
    server.exe = server.exe or '/nonexistent/pwsh'
    verdict = server.parse('Get-Date')
    assert verdict.status == 'validator_crash'
    assert verdict.errors[0].id == 'no-sandbox'
    assert server.starts == 0


def test_missing_pwsh_is_unchecked():
    server = PwshServer()
    server.exe = None
    assert server.parse('1').status == 'unchecked'
