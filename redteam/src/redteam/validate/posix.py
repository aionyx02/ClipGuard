"""``bash -n`` / ``sh -n`` / ``zsh -n`` in the sandbox (S8 §2).

One process per item, payload on stdin, ``bash --norc --noprofile -n`` and
``zsh -f -n`` so no startup file is read. zsh is run with fork allowed (it
forks for ``$(...)`` in argument position even under ``-n``) but exec denied.

macOS ships bash 3.2, which does not look inside ``$(...)`` or backticks. A
bash >= 5 is preferred when installed; otherwise payloads with command
substitutions are cross-checked with ``zsh --emulate sh -f -n``.

Parser stderr can quote the payload, so only line numbers and fixed IDs are
taken from it.
"""

from __future__ import annotations

import os
import re
import sys

from redteam.models import Shell, SyntaxIssue, SyntaxVerdict

from . import sandbox

BASH_ENV = 'PASTEWARDEN_BASH'
ZSH_ENV = 'PASTEWARDEN_ZSH'
BASH_CANDIDATES = (
    '/opt/homebrew/bin/bash',
    '/usr/local/bin/bash',
    '/bin/bash',
    '/usr/bin/bash',
)
ZSH_CANDIDATES = ('/bin/zsh', '/usr/bin/zsh', '/opt/homebrew/bin/zsh')
SH_CANDIDATES = ('/bin/sh', '/usr/bin/sh')
# bash releases before 4 skip the inside of $(...) under -n (S8 §2).
BASH_MIN_FULL_CHECK = 4

# (pattern, issue id). Matched per stderr line; first match wins.
_BASH_MESSAGES = (
    (re.compile(r'unexpected EOF while looking for matching'), 'unclosed'),
    (re.compile(r'syntax error: unexpected end of file'), 'unexpected-eof'),
    (re.compile(r'syntax error near unexpected token'), 'unexpected-token'),
    (re.compile(r'conditional binary operator|conditional'), 'conditional'),
    (re.compile(r'syntax error'), 'syntax-error'),
)
_DASH_MESSAGES = (
    (re.compile(r'Syntax error: Unterminated'), 'unclosed'),
    (re.compile(r'Syntax error: end of file unexpected'), 'unexpected-eof'),
    (re.compile(r'Syntax error: .* unexpected'), 'unexpected-token'),
    (re.compile(r'Syntax error'), 'syntax-error'),
)
_ZSH_MESSAGES = (
    (re.compile(r'parse error'), 'parse-error'),
    (re.compile(r'unmatched'), 'unclosed'),
    (re.compile(r'closing brace expected'), 'unclosed'),
    (re.compile(r'bad substitution|bad pattern|bad math'), 'bad-expansion'),
)
# zsh -n still performs some expansions; these are parse-time IO, not
# syntax errors, and never count as a pass.
_ZSH_IO = re.compile(
    r'no such file|permission denied|operation not permitted|fork failed|'
    r'is a directory|out of heap|out of memory|not a directory',
    re.IGNORECASE,
)
_LINE = re.compile(r'line (\d+):|^[^:]*: (\d+): |^zsh:(\d+):')


def _first(*candidates: str) -> str | None:
    return sandbox.find_executable(*candidates)


class PosixValidator:
    def __init__(
        self,
        timeout_ms: int = sandbox.VALIDATOR_TIMEOUT_MS,
        workspace: sandbox.Workspace | None = None,
    ) -> None:
        self.timeout_ms = timeout_ms
        # None: a fresh temp dir per run (tests pass a shared one).
        self.workspace = workspace
        self.bash = _first(os.environ.get(BASH_ENV, ''), *BASH_CANDIDATES)
        self.zsh = _first(os.environ.get(ZSH_ENV, ''), *ZSH_CANDIDATES)
        self.sh = None if sys.platform == 'darwin' else _first(*SH_CANDIDATES)
        self._bash_major: int | None = None

    # -- helpers ---------------------------------------------------------

    def bash_major(self) -> int | None:
        """Major version of the selected bash (asked inside the sandbox)."""
        if self._bash_major is None and self.bash:
            res = sandbox.run(
                sandbox.ExecSpec(self.bash, ('--version',)),
                b'',
                timeout_ms=self.timeout_ms,
                workspace=self.workspace,
            )
            m = re.search(rb'version (\d+)\.', res.stdout or b'')
            self._bash_major = int(m.group(1)) if m else 0
        return self._bash_major

    def _spec(self, shell: Shell) -> tuple[sandbox.ExecSpec, str] | None:
        if shell is Shell.ZSH:
            if not self.zsh:
                return None
            return (
                sandbox.ExecSpec(self.zsh, ('-f', '-n'), allow_fork=True),
                'zsh',
            )
        if shell is Shell.SH:
            if self.sh:
                # On Linux /bin/sh resolves to dash (or bash in sh mode).
                kind = 'bash' if os.path.basename(self.sh) == 'bash' else 'sh'
                return sandbox.ExecSpec(self.sh, ('-n',)), kind
            # macOS /bin/sh is a trampoline that execs bash, which the
            # sandbox forbids; run bash in POSIX mode directly instead.
            if not self.bash:
                return None
            return (
                sandbox.ExecSpec(
                    self.bash, ('--norc', '--noprofile', '--posix', '-n')
                ),
                'bash',
            )
        if not self.bash:
            return None
        return (
            sandbox.ExecSpec(self.bash, ('--norc', '--noprofile', '-n')),
            'bash',
        )

    # -- public ----------------------------------------------------------

    def available(self, shell: Shell) -> bool:
        return self._spec(shell) is not None

    def parse(self, src: str, shell: Shell) -> SyntaxVerdict:
        spec = self._spec(shell)
        if spec is None:
            return SyntaxVerdict(
                shell=shell,
                status='unchecked',
                errors=(SyntaxIssue(id=f'{shell.value}.missing'),),
            )
        verdict = self._run(spec[0], spec[1], src, shell)
        if (
            verdict.status == 'ok'
            and spec[1] == 'bash'
            and ('$(' in src or '`' in src)
            and (self.bash_major() or 0) < BASH_MIN_FULL_CHECK
            and self.zsh
        ):
            verdict = self._crosscheck(src, shell)
        return verdict

    def _crosscheck(self, src: str, shell: Shell) -> SyntaxVerdict:
        zsh = self.zsh or ''
        spec = sandbox.ExecSpec(
            zsh, ('--emulate', 'sh', '-f', '-n'), allow_fork=True
        )
        res = self._run(spec, 'zsh', src, shell)
        if res.status != 'invalid':
            # zsh could not decide (parse-time IO, crash): keep bash's ok.
            return SyntaxVerdict(shell=shell, status='ok')
        return SyntaxVerdict(
            shell=shell,
            status='invalid',
            errors=tuple(
                SyntaxIssue(id=f'bash.zsh-crosscheck.{e.id}', line=e.line)
                for e in res.errors
            ),
        )

    def _run(
        self, spec: sandbox.ExecSpec, kind: str, src: str, shell: Shell
    ) -> SyntaxVerdict:
        res = sandbox.run(
            spec,
            src.encode('utf-8', 'surrogatepass'),
            timeout_ms=self.timeout_ms,
            workspace=self.workspace,
        )
        if res.failure is not None:
            return SyntaxVerdict(
                shell=shell,
                status='validator_crash',
                errors=(SyntaxIssue(id=sandbox.failure_id(kind, res.failure)),),
            )
        issues, io = _classify(kind, res.stderr)
        if io:
            return SyntaxVerdict(
                shell=shell,
                status='validator_crash',
                errors=(SyntaxIssue(id=f'{kind}.parse-time-io'),),
            )
        if issues:
            return SyntaxVerdict(shell=shell, status='invalid', errors=issues)
        if res.returncode == 0:
            return SyntaxVerdict(shell=shell, status='ok')
        if res.returncode in (1, 2):
            return SyntaxVerdict(
                shell=shell,
                status='invalid',
                errors=(SyntaxIssue(id=f'{kind}.syntax-error'),),
            )
        return SyntaxVerdict(
            shell=shell,
            status='validator_crash',
            errors=(SyntaxIssue(id=f'{kind}.exit-{res.returncode}'),),
        )


def _classify(kind: str, stderr: bytes) -> tuple[tuple[SyntaxIssue, ...], bool]:
    table = {
        'bash': _BASH_MESSAGES,
        'sh': _DASH_MESSAGES,
        'zsh': _ZSH_MESSAGES,
    }[kind]
    issues: list[SyntaxIssue] = []
    io = False
    for raw in stderr.decode('utf-8', 'replace').splitlines()[:50]:
        # bash echoes the offending source line as "line N: `...'": skip it.
        if re.search(r'(line \d+|: \d+): `', raw) or 'warning:' in raw:
            continue
        if kind == 'zsh' and _ZSH_IO.search(raw):
            io = True
            continue
        for pattern, issue in table:
            if pattern.search(raw):
                m = _LINE.search(raw)
                line = None
                if m:
                    line = int(next(g for g in m.groups() if g))
                issues.append(SyntaxIssue(id=f'{kind}.{issue}', line=line))
                break
    return tuple(issues), io
