"""The sandbox itself: env, limits, network, filesystem, exec, refusal.

These tests run *our own* harmless scripts (never red-team payloads) with
bash executing them inside the sandbox, to prove the sandbox blocks what
the validators must never be able to do.
"""

import os
import socket
import sys
import threading
import time
from pathlib import Path

import pytest
from conftest import require

from redteam.models import Shell
from redteam.validate import Validator, sandbox
from redteam.validate.posix import PosixValidator


@pytest.fixture
def bash():
    require(Shell.BASH)
    return PosixValidator().bash


def run_bash(bash, script, workspace=None, timeout_ms=None, **kw):
    return sandbox.run(
        sandbox.ExecSpec(bash, ('--norc', '--noprofile'), **kw),
        script.encode(),
        workspace=workspace,
        timeout_ms=timeout_ms or sandbox.VALIDATOR_TIMEOUT_MS,
    )


def test_backend_detected_on_dev_machines():
    if sys.platform == 'darwin':
        assert sandbox.backend() == 'sandbox-exec'


def test_minimal_environment(bash, workspace, monkeypatch):
    monkeypatch.setenv('PASTEWARDEN_LEAK_CHECK', '1')
    monkeypatch.setenv('BASH_ENV', '/nonexistent.invalid')
    res = run_bash(bash, 'export -p', workspace)
    assert res.failure is None
    text = res.stdout.decode()
    assert 'PASTEWARDEN_LEAK_CHECK' not in text
    assert 'BASH_ENV' not in text
    assert f'HOME="{workspace.home}"' in text
    assert f'TMPDIR="{workspace.tmp}"' in text
    assert f'PSModulePath="{workspace.empty}"' in text
    assert 'POWERSHELL_TELEMETRY_OPTOUT="1"' in text
    path = next(ln for ln in text.splitlines() if ' PATH=' in ln)
    assert '/usr/bin:/bin' in path


def test_cwd_is_empty_temp_dir(bash, workspace):
    res = run_bash(bash, 'pwd; echo *', workspace)
    lines = res.stdout.decode().splitlines()
    assert Path(lines[0]).resolve() == workspace.cwd
    assert lines[1] == '*'


def test_payload_never_in_argv():
    spec = sandbox.ExecSpec('/bin/bash', ('--norc', '-n'))
    ws = sandbox.Workspace()
    try:
        argv = sandbox._argv(spec, ws, sandbox.backend() or 'container')
    finally:
        ws.close()
    assert argv[-2:] == ['--norc', '-n']


def test_timeout_kills_process_group(bash, workspace):
    start = time.monotonic()
    res = run_bash(bash, 'while :; do :; done', workspace, timeout_ms=500)
    assert res.failure == 'timeout'
    assert time.monotonic() - start < 2


def test_output_cap(bash, workspace):
    res = run_bash(bash, 'while :; do echo aaaaaaaaaaaaaaaa; done', workspace)
    assert res.failure == 'output-cap'


def test_rss_watchdog(bash, workspace):
    res = run_bash(
        bash, 'x=a; while :; do x="$x$x"; done', workspace, timeout_ms=5000
    )
    assert res.failure in ('rss-limit', 'signal', 'timeout')
    assert res.failure != 'timeout' or sys.platform != 'darwin'


def test_write_outside_temp_dir_denied(bash, workspace, tmp_path):
    if sandbox.backend() == 'container':
        pytest.skip('container: /tmp is the writable tmpfs by design')
    target = tmp_path / 'outside-marker'
    res = run_bash(bash, f': > {target}', workspace)
    assert res.failure is None
    assert not target.exists()
    res = run_bash(bash, f': > {workspace.cwd / "inside"}', workspace)
    assert (workspace.cwd / 'inside').exists()


@pytest.mark.skipif(sys.platform != 'darwin', reason='sandbox-exec only')
def test_exec_denied(bash, workspace):
    res = run_bash(bash, '/usr/bin/true && echo RAN', workspace)
    assert b'RAN' not in res.stdout


@pytest.mark.skipif(sys.platform != 'darwin', reason='sandbox-exec only')
def test_fork_denied_unless_allowed(bash, workspace):
    res = run_bash(bash, '( echo SUB )', workspace)
    assert b'SUB' not in res.stdout
    res = run_bash(bash, '( echo SUB )', workspace, allow_fork=True)
    assert b'SUB' in res.stdout


@pytest.mark.skipif(sys.platform != 'darwin', reason='sandbox-exec only')
def test_home_contents_unreadable(bash, workspace):
    here = Path(__file__).resolve()
    if not here.is_relative_to(Path.home().resolve()):
        pytest.skip('checkout is not under $HOME')
    res = run_bash(bash, f'read -r line < {here} && echo READ', workspace)
    assert b'READ' not in res.stdout


def test_network_denied_loopback(bash, workspace):
    if sandbox.backend() == 'container':
        pytest.skip('container: --network none leaves only lo, shared')
    srv = socket.socket()
    srv.bind(('127.0.0.1', 0))
    srv.listen(1)
    srv.settimeout(3)
    port = srv.getsockname()[1]
    accepted = []

    def accept():
        try:
            conn, _ = srv.accept()
            accepted.append(conn)
        except OSError:
            pass

    t = threading.Thread(target=accept)
    t.start()
    res = run_bash(
        bash, f'exec 3<>/dev/tcp/127.0.0.1/{port} && echo CONNECTED', workspace
    )
    srv.close()
    t.join()
    assert b'CONNECTED' not in res.stdout
    assert accepted == []


def test_network_denied_external(bash, workspace):
    # 192.0.2.1 is TEST-NET-1 (RFC 5737): never routable.
    res = run_bash(
        bash, 'exec 3<>/dev/tcp/192.0.2.1/80 && echo CONNECTED', workspace
    )
    assert b'CONNECTED' not in res.stdout


def test_pwsh_network_denied(workspace):
    """pwsh itself (the binary the server runs) cannot open sockets."""
    require(Shell.POWERSHELL)
    from redteam.validate.pwsh_server import PWSH_DOTNET_ENV, find_pwsh

    script = workspace.root / 'net.ps1'
    script.write_text(
        'try { [System.Net.Sockets.TcpClient]::new("192.0.2.1", 80) | '
        'Out-Null; "CONNECTED" } catch { "blocked" }\n'
        'try { [System.Net.Dns]::GetHostAddresses("example.invalid") | '
        'Out-Null; "RESOLVED" } catch { "blocked" }\n'
    )
    res = sandbox.run(
        sandbox.ExecSpec(
            find_pwsh(),
            ('-NoProfile', '-NonInteractive', '-File', str(script)),
            rlimit_as=False,
            env=PWSH_DOTNET_ENV,
        ),
        b'',
        workspace=workspace,
        timeout_ms=15_000,
    )
    assert res.failure is None
    assert b'CONNECTED' not in res.stdout
    assert b'RESOLVED' not in res.stdout


def test_no_sandbox_means_no_run(monkeypatch):
    monkeypatch.setattr(sandbox, 'backend', lambda: None)

    def boom(*a, **k):
        raise AssertionError('must not spawn without a sandbox')

    monkeypatch.setattr(sandbox.subprocess, 'Popen', boom)
    res = sandbox.run(sandbox.ExecSpec('/bin/bash'), b'echo')
    assert res.failure == 'no-sandbox'
    with Validator() as v:
        for shell in (Shell.BASH, Shell.ZSH, Shell.SH, Shell.POWERSHELL):
            verdict = v.validate('echo a', shell)
            assert verdict.status in ('validator_crash', 'unchecked')
            if verdict.status == 'validator_crash':
                assert verdict.errors[0].id == 'no-sandbox'


def test_container_backend_requires_verified_lockdown(monkeypatch):
    monkeypatch.setenv(sandbox.CONTAINER_ENV, 'container')
    if sys.platform.startswith('linux') and sandbox._container_ok():
        pytest.skip('really inside the locked-down container')
    assert not sandbox._container_ok()


def test_bwrap_argv_unshares_everything(workspace):
    spec = sandbox.ExecSpec('/usr/bin/zsh', ('-f', '-n'))
    argv = sandbox._argv(spec, workspace, 'bwrap')
    assert '--unshare-all' in argv and '--die-with-parent' in argv
    assert argv[-3:] == ['/usr/bin/zsh', '-f', '-n']


def test_workspace_cleanup():
    ws = sandbox.Workspace()
    root = ws.root
    assert root.is_dir()
    ws.close()
    assert not os.path.exists(root)
