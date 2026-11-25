"""Long-running sandboxed pwsh parse server (S8 §1, phase-5.md §5.3.5).

``psparse-server.ps1`` speaks JSONL: ``{id, src}`` in,
``{id, ok, errors: [{id, line, column}]}`` out. One server handles up to
``PWSH_RESTART_EVERY`` items, then it is restarted; any timeout, crash,
protocol error or id mismatch kills it, the item becomes
``validator_crash`` and the next item starts a fresh server.

Payloads that contain ``using module`` / ``using assembly`` (or
``Import-DscResource``) are refused before anything is sent: the parser reads
modules and loads assemblies for those at parse time.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import unicodedata
from pathlib import Path

from redteam.models import Shell, SyntaxIssue, SyntaxVerdict

from . import sandbox

PWSH_RESTART_EVERY = 5_000
SERVER_SCRIPT = Path(__file__).with_name('psparse-server.ps1')
PWSH_ENV = 'PASTEWARDEN_PWSH'
PWSH_CANDIDATES = (
    '~/.local/bin/pwsh',
    '/opt/homebrew/bin/pwsh',
    '/usr/local/bin/pwsh',
    '/opt/microsoft/powershell/7/pwsh',
    '/usr/bin/pwsh',
    'pwsh',
)
# .NET reserves a large virtual range for the GC unless capped; the cap also
# keeps the server well under the RSS watchdog.
PWSH_DOTNET_ENV = (
    ('DOTNET_SYSTEM_GLOBALIZATION_INVARIANT', '1'),
    ('DOTNET_GCHeapHardLimit', '0x10000000'),
    ('DOTNET_TieredPGO', '0'),
)

# Parse-time IO in the PowerShell parser (S8 §1). Matched after removing
# backticks (escapes and line continuations), block comments and format
# characters, so `u`sing  <# x #> module and line breaks do not hide it.
_UNSAFE = re.compile(
    r'using\s+(?:module|assembly)\b|import-dscresource\b',
    re.IGNORECASE,
)
_BLOCK_COMMENT = re.compile(r'<#.*?(?:#>|\Z)', re.DOTALL)


def is_unsafe(src: str) -> bool:
    """True if the PowerShell parser could touch files for this input."""
    text = ''.join(
        ch for ch in src if unicodedata.category(ch) != 'Cf' and ch != '`'
    )
    text = _BLOCK_COMMENT.sub(' ', text)
    return _UNSAFE.search(text) is not None


def find_pwsh() -> str | None:
    return sandbox.find_executable(
        os.environ.get(PWSH_ENV, ''), *PWSH_CANDIDATES
    )


def _crash(issue_id: str) -> SyntaxVerdict:
    return SyntaxVerdict(
        shell=Shell.POWERSHELL,
        status='validator_crash',
        errors=(SyntaxIssue(id=issue_id),),
    )


def _utf16_to_cp_column(src: str, line: int, column: int) -> int:
    """pwsh columns count UTF-16 units; SyntaxIssue columns count chars."""
    lines = src.split('\n')
    if not 1 <= line <= len(lines):
        return column
    units = 0
    for i, ch in enumerate(lines[line - 1]):
        if units >= column - 1:
            return i + 1
        units += 2 if ord(ch) > 0xFFFF else 1
    return len(lines[line - 1]) + 1


_ERROR_ID = re.compile(r'[A-Za-z0-9_.]{1,80}')


def _issue_id(raw: object) -> str:
    if isinstance(raw, str) and _ERROR_ID.fullmatch(raw):
        return f'pwsh.{raw}'
    return 'pwsh.unknown'


class PwshServer:
    """Owns one sandboxed pwsh process (restarted as needed)."""

    def __init__(
        self,
        timeout_ms: int = sandbox.VALIDATOR_TIMEOUT_MS,
        workspace: sandbox.Workspace | None = None,
    ) -> None:
        self.timeout_ms = timeout_ms
        self._shared_ws = workspace
        self.exe = find_pwsh()
        self._ws: sandbox.Workspace | None = None
        self._server: sandbox.Server | None = None
        self._served = 0
        self._next_id = 0
        self.starts = 0
        self.sent = 0

    @property
    def available(self) -> bool:
        return self.exe is not None

    def _ensure(self) -> str | None:
        """Start the server if needed; return a failure id or None."""
        if self._server is not None and self._server.alive:
            if self._served < PWSH_RESTART_EVERY:
                return None
        self._stop()
        if sandbox.backend() is None:
            return 'no-sandbox'
        if self.exe is None:
            return 'pwsh.missing'
        self._ws = self._shared_ws or sandbox.Workspace()
        script = self._ws.root / 'psparse-server.ps1'
        shutil.copyfile(SERVER_SCRIPT, script)
        spec = sandbox.ExecSpec(
            exe=self.exe,
            args=(
                '-NoProfile',
                '-NonInteractive',
                '-NoLogo',
                '-File',
                str(script),
            ),
            rlimit_as=False,
            env=PWSH_DOTNET_ENV,
        )
        self._server = sandbox.Server(spec, self._ws)
        self.starts += 1
        ready = self._server.start()
        if isinstance(ready, sandbox.Failure):
            self._stop()
            return sandbox.failure_id('pwsh', ready)
        try:
            ok = json.loads(ready).get('ready') is True
        except (ValueError, AttributeError):
            ok = False
        if not ok:
            self._stop()
            return 'pwsh.protocol'
        self._served = 0
        return None

    def parse(self, src: str) -> SyntaxVerdict:
        if self.exe is None:
            return SyntaxVerdict(
                shell=Shell.POWERSHELL,
                status='unchecked',
                errors=(SyntaxIssue(id='pwsh.missing'),),
            )
        if is_unsafe(src):
            return SyntaxVerdict(
                shell=Shell.POWERSHELL,
                status='rejected_unsafe',
                errors=(SyntaxIssue(id='pwsh.using-module-or-assembly'),),
            )
        failed = self._ensure()
        if failed:
            return _crash(failed)
        if self._server is None:
            return _crash('pwsh.closed')
        self._next_id += 1
        req_id = self._next_id
        line = json.dumps({'id': req_id, 'src': src}, ensure_ascii=True)
        self._served += 1
        self.sent += 1
        resp = self._server.request(line.encode('ascii'), self.timeout_ms)
        if isinstance(resp, sandbox.Failure):
            self._stop()
            return _crash(sandbox.failure_id('pwsh', resp))
        try:
            data = json.loads(resp)
            if not isinstance(data, dict) or data.get('id') != req_id:
                raise ValueError
            if 'fatal' in data:
                raise ValueError
            ok = data['ok']
            errors = tuple(
                SyntaxIssue(
                    id=_issue_id(e['id']),
                    line=int(e['line']),
                    column=_utf16_to_cp_column(
                        src, int(e['line']), int(e['column'])
                    ),
                )
                for e in data['errors']
            )
            if not isinstance(ok, bool) or ok != (not errors):
                raise ValueError
        except (ValueError, KeyError, TypeError):
            self._stop()
            return _crash('pwsh.protocol')
        return SyntaxVerdict(
            shell=Shell.POWERSHELL,
            status='ok' if ok else 'invalid',
            errors=errors,
        )

    def _stop(self) -> None:
        if self._server is not None:
            self._server.close()
            self._server = None
        if self._ws is not None and self._ws is not self._shared_ws:
            self._ws.close()
            self._ws = None

    def close(self) -> None:
        self._stop()

    def __enter__(self) -> PwshServer:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
