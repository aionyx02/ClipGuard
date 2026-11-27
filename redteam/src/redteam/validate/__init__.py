"""Sandboxed, never-executing syntax validation (phase-5.md §5.3.5, S8).

Usage::

    from redteam.validate import Validator, validate

    verdict = validate(payload)  # one-off; starts and stops pwsh

    with Validator() as v:  # keeps the pwsh parse server alive
        for item in items:
            verdict = v.validate(item.payload, item.shell)

Payloads are only ever handed to parsers on stdin inside an OS sandbox
(``sandbox.py``); they are never executed, never put on a clipboard, never
logged. A timeout, crash or protocol error is ``validator_crash`` and never
counts as valid; a missing sandbox is ``validator_crash`` with
``no-sandbox``; a missing parser binary is ``unchecked``.
"""

from __future__ import annotations

from redteam.models import Shell, SyntaxIssue, SyntaxVerdict

from . import cmd_tokenizer, osa, recurse, router
from .posix import PosixValidator
from .pwsh_server import PwshServer
from .sandbox import VALIDATOR_TIMEOUT_MS, Workspace

__all__ = [
    'MAX_PAYLOAD_BYTES',
    'Validator',
    'effective_status',
    'flatten_errors',
    'validate',
]

# Anything bigger is refused (validator_crash, payload-too-large): the core
# reads at most a few hundred KiB, and parsers do not need more.
MAX_PAYLOAD_BYTES = 256 * 1024


def _verdict(
    shell: Shell, status: str, issue_id: str | None = None
) -> SyntaxVerdict:
    errors = (SyntaxIssue(id=issue_id),) if issue_id else ()
    return SyntaxVerdict(shell=shell, status=status, errors=errors)


class Validator:
    """Reusable validator; not thread-safe. Use as a context manager."""

    def __init__(
        self,
        timeout_ms: int = VALIDATOR_TIMEOUT_MS,
        workspace: Workspace | None = None,
    ) -> None:
        """``workspace``: share one temp dir across runs (tests use it to
        put markers where a sandboxed process could write); by default every
        run gets a fresh one."""
        self.timeout_ms = timeout_ms
        self.workspace = workspace
        self.pwsh = PwshServer(timeout_ms, workspace)
        self.posix = PosixValidator(timeout_ms, workspace)

    def __enter__(self) -> Validator:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        self.pwsh.close()

    def validate(
        self, payload: str, shell: Shell | None = None
    ) -> SyntaxVerdict:
        if shell is None:
            shell = router.route(payload)
        return self._validate(payload, Shell(shell), 0)

    def _outer(self, payload: str, shell: Shell) -> SyntaxVerdict:
        if len(payload.encode('utf-8', 'surrogatepass')) > MAX_PAYLOAD_BYTES:
            return _verdict(shell, 'validator_crash', 'payload-too-large')
        if shell is Shell.CMD:
            issues = cmd_tokenizer.check(payload)
            return SyntaxVerdict(
                shell=shell,
                status='invalid' if issues else 'ok',
                errors=issues,
            )
        if shell is Shell.POWERSHELL:
            return self.pwsh.parse(payload)
        if shell is Shell.APPLESCRIPT:
            return osa.parse(payload, self.timeout_ms, self.workspace)
        return self.posix.parse(payload, shell)

    def _validate(
        self, payload: str, shell: Shell, depth: int
    ) -> SyntaxVerdict:
        outer = self._outer(payload, shell)
        if outer.status not in ('ok', 'invalid'):
            return outer
        found = recurse.find_inner(payload, shell)
        if not found:
            return outer
        inner: list[SyntaxVerdict] = []
        if depth >= recurse.RECURSE_MAX_DEPTH:
            inner.append(_verdict(shell, 'unchecked', 'recurse.max-depth'))
        else:
            for item in found[: recurse.RECURSE_MAX_INNER]:
                if item.error:
                    inner.append(_verdict(item.shell, 'invalid', item.error))
                else:
                    inner.append(
                        self._validate(item.src, item.shell, depth + 1)
                    )
            if len(found) > recurse.RECURSE_MAX_INNER:
                inner.append(_verdict(shell, 'unchecked', 'recurse.too-many'))
        return SyntaxVerdict(
            shell=outer.shell,
            status=outer.status,
            errors=outer.errors,
            inner=tuple(inner),
        )


def validate(payload: str, shell: Shell | None = None) -> SyntaxVerdict:
    """Validate one payload (starts a fresh pwsh server if one is needed)."""
    with Validator() as v:
        return v.validate(payload, shell)


def effective_status(verdict: SyntaxVerdict) -> str:
    """``ok`` only if the payload and every nested script are ok."""
    if verdict.status != 'ok':
        return verdict.status
    for inner in verdict.inner:
        status = effective_status(inner)
        if status != 'ok':
            return status
    return 'ok'


def flatten_errors(verdict: SyntaxVerdict) -> tuple[SyntaxIssue, ...]:
    """Outer errors, then nested ones (positions are relative to each
    nested script)."""
    out = list(verdict.errors)
    for inner in verdict.inner:
        out.extend(flatten_errors(inner))
    return tuple(out)
