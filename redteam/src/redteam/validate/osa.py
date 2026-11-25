"""AppleScript / JXA compile check with ``osacompile`` (S8 §4, macOS only).

``osacompile -o /dev/null`` compiles without running (``do shell script``
and JXA bodies are not executed), but resolving ``tell application "X"``
launches X to read its scripting dictionary. So application references are
rewritten before compiling, and the sandbox also denies exec and
LaunchServices. ``osascript`` is never used.

Deviation from phase-5.md §5.3.5 (measured on macOS 27): rewriting to
``application id "invalid.pastewarden"`` makes *every* ``tell`` block fail
with -1728 ("Can't get application id"), and the name form
``application "invalid.pastewarden"`` blocks on a "Where is ...?" dialog
until the timeout. References are therefore rewritten to ``me``
(``tell me``), and ``using terms from <app>`` blocks to ``if true then``.
App-specific terminology (System Events' ``keystroke ... using``) then fails
to compile: that is reported as ``invalid``, a known false negative.
"""

from __future__ import annotations

import re
import sys

from redteam.models import Shell, SyntaxIssue, SyntaxVerdict

from . import sandbox

OSACOMPILE = '/usr/bin/osacompile'
PLACEHOLDER_APP_ID = 'invalid.pastewarden'

_USING_TERMS = re.compile(
    r'\busing\s+terms\s+from\s+(?:application|app)\s+(?:id\s+)?'
    r'"(?:[^"\\\n]|\\.)*"',
    re.IGNORECASE,
)
_END_USING_TERMS = re.compile(r'\bend\s+using\s+terms\s+from\b', re.I)
_APP_REF = re.compile(
    r'\b(?:application|app)\s+(?:id\s+)?"(?:[^"\\\n]|\\.)*"',
    re.IGNORECASE,
)
_JXA_APP = re.compile(r'\bApplication\s*\(\s*(?:\'[^\'\n]*\'|"[^"\n]*")\s*\)')
_JXA_HINT = re.compile(
    r'\bApplication\s*\(|\bObjC\.|\bfunction\b|\bconst\b|\blet\b|=>|'
    r'\bvar\s+\w+\s*=|;\s*$',
    re.MULTILINE,
)
_OSA_CODE = re.compile(rb'\((-\d{1,6})\)')


def rewrite_apps(src: str) -> str:
    """Remove every reference to a real application (see module doc)."""
    src = _USING_TERMS.sub('if true then', src)
    src = _END_USING_TERMS.sub('end if', src)
    src = _APP_REF.sub('me', src)
    return _JXA_APP.sub(f"Application('{PLACEHOLDER_APP_ID}')", src)


def looks_like_jxa(src: str) -> bool:
    return bool(_JXA_HINT.search(src)) and 'tell application' not in src


def available() -> bool:
    return sys.platform == 'darwin' and (
        sandbox.find_executable(OSACOMPILE) is not None
    )


def parse(
    src: str,
    timeout_ms: int = sandbox.VALIDATOR_TIMEOUT_MS,
    workspace: sandbox.Workspace | None = None,
) -> SyntaxVerdict:
    if not available():
        return SyntaxVerdict(
            shell=Shell.APPLESCRIPT,
            status='unchecked',
            errors=(SyntaxIssue(id='osa.missing'),),
        )
    args: tuple[str, ...] = ('-o', '/dev/null')
    if looks_like_jxa(src):
        args = ('-l', 'JavaScript', *args)
    res = sandbox.run(
        sandbox.ExecSpec(OSACOMPILE, args),
        rewrite_apps(src).encode('utf-8', 'surrogatepass'),
        timeout_ms=timeout_ms,
        workspace=workspace,
    )
    if res.failure is not None:
        return SyntaxVerdict(
            shell=Shell.APPLESCRIPT,
            status='validator_crash',
            errors=(SyntaxIssue(id=sandbox.failure_id('osa', res.failure)),),
        )
    if res.returncode == 0:
        return SyntaxVerdict(shell=Shell.APPLESCRIPT, status='ok')
    if res.returncode == 1:
        m = _OSA_CODE.search(res.stderr)
        code = m.group(1).decode('ascii') if m else 'error'
        return SyntaxVerdict(
            shell=Shell.APPLESCRIPT,
            status='invalid',
            errors=(SyntaxIssue(id=f'osa.{code}'),),
        )
    return SyntaxVerdict(
        shell=Shell.APPLESCRIPT,
        status='validator_crash',
        errors=(SyntaxIssue(id=f'osa.exit-{res.returncode}'),),
    )
