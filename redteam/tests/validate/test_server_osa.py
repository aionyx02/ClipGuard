"""JSONL server (``python -m redteam.validate.server``) and osacompile."""

import io
import json
import subprocess
import sys
from pathlib import Path

import pytest
from conftest import J, require

from redteam.models import Shell
from redteam.validate import Validator, osa, server

SENTINEL = 'pastewardensentinel'


def serve(lines):
    out = io.StringIO()
    data = b''.join(
        (ln if isinstance(ln, bytes) else json.dumps(ln).encode()) + b'\n'
        for ln in lines
    )
    assert server.serve(io.BytesIO(data), out) == 0
    return [json.loads(x) for x in out.getvalue().splitlines()]


def test_jsonl_shape_and_ids():
    a, b = serve(
        [
            {'id': 1, 'shell': 'cmd', 'src': f'echo {SENTINEL} |'},
            {'id': 'two', 'shell': 'cmd', 'src': f'echo {SENTINEL}'},
        ]
    )
    assert a['id'] == 1 and a['shell'] == 'cmd'
    assert a['status'] == 'invalid' and a['ok'] is False
    assert a['errors'] == [
        {'id': 'cmd.dangling-operator', 'line': 1, 'column': 26}
    ]
    assert b == {
        'id': 'two',
        'shell': 'cmd',
        'status': 'ok',
        'ok': True,
        'errors': [],
        'inner': [],
    }


def test_protocol_errors():
    replies = serve(
        [
            b'not json',
            b'[1, 2]',
            {'id': 3},
            {'id': 4, 'shell': 'fish', 'src': 'echo'},
            {'id': True, 'shell': 'cmd', 'src': 'echo'},
        ]
    )
    ids = [r['errors'][0]['id'] for r in replies[:4]]
    assert ids == [
        'protocol.bad-json',
        'protocol.bad-request',
        'protocol.missing-src',
        'protocol.unknown-shell',
    ]
    assert all(r['status'] == 'validator_crash' for r in replies[:4])
    assert replies[2]['id'] == 3
    assert replies[4]['id'] is None and replies[4]['status'] == 'ok'


def test_oversized_request_is_refused():
    big = {'id': 1, 'shell': 'cmd', 'src': 'a' * (server.MAX_REQUEST_BYTES)}
    reply, after = serve([big, {'id': 2, 'shell': 'cmd', 'src': 'echo'}])
    assert reply['errors'][0]['id'] == 'protocol.request-too-large'
    assert after['id'] == 2 and after['status'] == 'ok'


def test_payload_too_large_is_crash():
    with Validator() as v:
        verdict = v.validate('a' * (300 * 1024), Shell.CMD)
    assert verdict.status == 'validator_crash'
    assert verdict.errors[0].id == 'payload-too-large'


def test_effective_status_includes_inner():
    (reply,) = serve(
        [{'id': 1, 'shell': 'cmd', 'src': J('cmd /c "echo ', SENTINEL, ' |"')}]
    )
    assert reply['status'] == 'invalid' and reply['ok'] is False
    assert reply['inner'][0]['errors'][0]['id'] == 'cmd.dangling-operator'


def test_module_entrypoint_never_echoes_src():
    """End to end, as the Rust MCP tool spawns it."""
    lines = [
        {'id': 1, 'shell': 'cmd', 'src': f'echo {SENTINEL} &&'},
        {'id': 2, 'shell': 'bash', 'src': f'echo {SENTINEL} )'},
        {'id': 3, 'src': f'Write-Output {SENTINEL} (('},
        {
            'id': 4,
            'shell': 'powershell',
            'src': J('us', f'ing module {SENTINEL}'),
        },
    ]
    data = ''.join(json.dumps(x) + '\n' for x in lines)
    proc = subprocess.run(
        [sys.executable, '-m', 'redteam.validate.server'],
        input=data,
        capture_output=True,
        text=True,
        timeout=60,
        cwd=Path(__file__).resolve().parents[2],
        check=False,
    )
    assert proc.returncode == 0
    assert SENTINEL not in proc.stdout
    assert SENTINEL not in proc.stderr
    replies = [json.loads(x) for x in proc.stdout.splitlines()]
    assert [r['id'] for r in replies] == [1, 2, 3, 4]
    assert replies[0]['status'] == 'invalid'
    assert replies[3]['status'] in ('rejected_unsafe', 'unchecked')


# --- osacompile ---------------------------------------------------------


def test_rewrite_apps():
    src = (
        'tell application "TextEdit" to activate\n'
        'tell app id "com.example.x"\nend tell\n'
        'using terms from application "Mail"\nend using terms from\n'
        "Application('Finder').activate()"
    )
    out = osa.rewrite_apps(src)
    assert 'TextEdit' not in out and 'Mail' not in out
    assert 'com.example.x' not in out and 'Finder' not in out
    assert 'tell me to activate' in out
    assert 'if true then\nend if' in out


@pytest.mark.parametrize(
    ('src', 'status'),
    [
        ('display dialog "hi"', 'ok'),
        ('set x to 1 + 2', 'ok'),
        ('tell application "TextEdit"\nactivate\nend tell', 'ok'),
        ('set x to (1 +', 'invalid'),
        ('tell application "Finder"\nget name', 'invalid'),
        ('var x = 1;\nfunction f() { return x; }', 'ok'),
        ('var x = ;', 'invalid'),
    ],
)
def test_osacompile(src, status, shared_validator):
    require(Shell.APPLESCRIPT)
    verdict = shared_validator.validate(src, Shell.APPLESCRIPT)
    assert verdict.status == status, verdict
    if status == 'invalid':
        assert verdict.errors[0].id.startswith('osa.-')
