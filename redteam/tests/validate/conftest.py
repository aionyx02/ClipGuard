import os

import pytest

from redteam.models import Shell
from redteam.validate import Validator, osa, sandbox
from redteam.validate.posix import PosixValidator
from redteam.validate.pwsh_server import find_pwsh


def J(*parts: str) -> str:
    """Assemble command-like test strings at runtime (CLAUDE.md: Defender
    quarantines files containing whole malicious keywords)."""
    return ''.join(parts)


def _skip_reason(shell: Shell) -> str | None:
    if shell is Shell.CMD:
        return None
    if sandbox.backend() is None:
        return 'no sandbox backend (sandbox-exec / bwrap / container)'
    if shell is Shell.POWERSHELL:
        return None if find_pwsh() else 'pwsh not installed'
    if shell is Shell.APPLESCRIPT:
        return None if osa.available() else 'osacompile is macOS only'
    if not PosixValidator().available(shell):
        return f'{shell.value} not installed'
    return None


# Set in redteam/validate.Dockerfile: there, a missing validator is a
# failure, not a skip (CI must not go green by skipping everything).
REQUIRE_ENV = 'PASTEWARDEN_REQUIRE_VALIDATORS'


def require(shell: Shell) -> None:
    reason = _skip_reason(shell)
    if reason:
        required = os.environ.get(REQUIRE_ENV, '').split(',')
        if shell.value in required:
            pytest.fail(f'required validator unavailable: {reason}')
        pytest.skip(reason)


@pytest.fixture
def workspace():
    ws = sandbox.Workspace()
    yield ws
    ws.close()


@pytest.fixture
def validator(workspace):
    """A Validator whose runs share ``workspace``: markers placed in its
    cwd are somewhere a sandboxed process *could* write."""
    with Validator(workspace=workspace) as v:
        yield v


@pytest.fixture(scope='module')
def shared_validator():
    with Validator() as v:
        yield v
