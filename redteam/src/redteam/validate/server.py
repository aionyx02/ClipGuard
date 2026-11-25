"""JSONL validator server: ``python -m redteam.validate.server``.

Spawned by the Rust MCP ``validate_syntax`` tool (``--profile redteam``,
phase-5.md §5.7). One request per line on stdin::

    {"id": 1, "shell": "bash", "src": "..."}     # "shell" is optional

One response per line on stdout, never echoing ``src``::

    {"id": 1, "shell": "bash", "status": "ok", "ok": true,
     "errors": [{"id": "...", "line": 1, "column": 2}], "inner": [...]}

``status`` is the effective status (``ok`` only if every nested script is
ok); ``errors`` lists the outer errors followed by those of nested scripts;
``inner`` keeps the per-level detail (same shape without ``id``).
"""

from __future__ import annotations

import json
import sys
from typing import IO

from redteam.models import Shell, SyntaxVerdict

from . import MAX_PAYLOAD_BYTES, Validator, effective_status, flatten_errors

# JSON escaping can grow text up to 6x (\uXXXX); allow that plus framing.
MAX_REQUEST_BYTES = MAX_PAYLOAD_BYTES * 6 + 1024


def _issues(issues) -> list[dict[str, object]]:
    return [{'id': e.id, 'line': e.line, 'column': e.column} for e in issues]


def _detail(verdict: SyntaxVerdict) -> dict[str, object]:
    return {
        'shell': verdict.shell.value,
        'status': verdict.status,
        'ok': verdict.ok,
        'errors': _issues(verdict.errors),
        'inner': [_detail(i) for i in verdict.inner],
    }


def response(req_id: object, verdict: SyntaxVerdict) -> dict[str, object]:
    return {
        'id': req_id,
        'shell': verdict.shell.value,
        'status': effective_status(verdict),
        'ok': verdict.ok,
        'errors': _issues(flatten_errors(verdict)),
        'inner': [_detail(i) for i in verdict.inner],
    }


def _bad_request(req_id: object, issue_id: str) -> dict[str, object]:
    return {
        'id': req_id,
        'shell': None,
        'status': 'validator_crash',
        'ok': False,
        'errors': [{'id': issue_id, 'line': None, 'column': None}],
        'inner': [],
    }


def handle(validator: Validator, line: bytes) -> dict[str, object]:
    if len(line) > MAX_REQUEST_BYTES:
        return _bad_request(None, 'protocol.request-too-large')
    try:
        req = json.loads(line)
    except (ValueError, UnicodeDecodeError):
        return _bad_request(None, 'protocol.bad-json')
    if not isinstance(req, dict):
        return _bad_request(None, 'protocol.bad-request')
    req_id = req.get('id')
    if not isinstance(req_id, (str, int)) or isinstance(req_id, bool):
        req_id = None
    src = req.get('src')
    if not isinstance(src, str):
        return _bad_request(req_id, 'protocol.missing-src')
    shell_name = req.get('shell')
    shell: Shell | None = None
    if shell_name is not None:
        try:
            shell = Shell(shell_name)
        except ValueError:
            return _bad_request(req_id, 'protocol.unknown-shell')
    try:
        verdict = validator.validate(src, shell)
    except Exception:  # noqa: BLE001 - never crash the server on one item
        return _bad_request(req_id, 'validator.internal-error')
    return response(req_id, verdict)


def serve(stdin: IO[bytes], stdout: IO[str]) -> int:
    with Validator() as validator:
        while True:
            line = stdin.readline(MAX_REQUEST_BYTES + 2)
            if not line:
                return 0
            if not line.endswith(b'\n') and len(line) > MAX_REQUEST_BYTES:
                # Drain the rest of an oversized line.
                while line and not line.endswith(b'\n'):
                    line = stdin.readline(65536)
                out = _bad_request(None, 'protocol.request-too-large')
            elif not line.strip():
                continue
            else:
                out = handle(validator, line)
            stdout.write(json.dumps(out, ensure_ascii=False) + '\n')
            stdout.flush()


def main() -> int:
    return serve(sys.stdin.buffer, sys.stdout)


if __name__ == '__main__':
    sys.exit(main())
