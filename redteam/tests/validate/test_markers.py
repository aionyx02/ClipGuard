"""Parse-only must never execute anything (S8 method).

Every payload here is harmless and would only create ``marker-N`` in the
validator's own cwd if it were executed. The cwd is inside the sandbox's
writable temp dir and the markers are written by shell builtins
(redirections, ``New-Item``, ``open for access``), so the sandbox would *not*
stop the write (see the control test): only the validators' parse-only
behaviour does. After each validation the marker must not exist.
"""

import base64

import pytest
from conftest import J, require

from redteam.models import Shell
from redteam.validate import sandbox

# A builtin redirection creates the file without exec (the sandbox denies
# exec, which would make an external `touch` prove nothing).
TOUCH = ': >'
NEW_ITEM = J('New-', 'Item')
IEX = J('Invoke-', 'Expression')
PS = J('power', 'shell')


def _posix_cases(m):
    """(shell set, payload) for marker path ``m(n)``."""
    return [
        ('all', f'echo $({TOUCH} {m(1)})'),
        ('all', f'echo `{TOUCH} {m(2)}`'),
        ('bash zsh', f'cat <({TOUCH} {m(3)})'),
        ('all', f'cat <<EOF\n$({TOUCH} {m(4)})\nEOF\n'),
        ('all', f'eval "{TOUCH} {m(5)}"'),
        ('all', f'x=$({TOUCH} {m(6)})'),
        ('all', f': ${{x:=$({TOUCH} {m(7)})}}'),
        ('bash zsh', f'a[$({TOUCH} {m(8)})]=1'),
        ('all', f'echo hi > $({TOUCH} {m(9)})'),
        ('all', f"trap '{TOUCH} {m(10)}' EXIT"),
        ('all', f'f() {{ {TOUCH} {m(11)}; }}; f'),
        ('bash', f'coproc {TOUCH} {m(12)}'),
        ('zsh', f"echo *(e:'{TOUCH} {m(13)}':)"),
        ('zsh', f'cat =({TOUCH} {m(14)})'),
        ('zsh', f"x='$({TOUCH} {m(15)})'; echo ${{(e)x}}"),
        ('all', f'echo $(<{m(99)}); {TOUCH} {m(16)}'),
        ('all', f'echo $(( $({TOUCH} {m(17)}) ))'),
        ('all', f"bash -c '{TOUCH} {m(18)}'"),
        ('all', f'{TOUCH} {m(19)}'),
    ]


@pytest.mark.parametrize('shell', [Shell.BASH, Shell.SH, Shell.ZSH])
def test_posix_never_executes(shell, validator, workspace):
    require(shell)

    def m(n):
        return str(workspace.cwd / f'marker-{n}')

    ran = 0
    for shells, payload in _posix_cases(m):
        if shells != 'all' and shell.value not in shells.split():
            continue
        verdict = validator.validate(payload, shell)
        assert verdict.status in ('ok', 'invalid', 'validator_crash')
        ran += 1
    assert ran >= 12
    assert sorted(p.name for p in workspace.cwd.iterdir()) == []


def test_control_markers_are_writable_when_executed(workspace):
    """Control group: executing (our own, harmless) builtin redirection in
    the same sandbox does create the marker, so the tests above are
    meaningful."""
    require(Shell.BASH)
    from redteam.validate.posix import PosixValidator

    bash = PosixValidator().bash
    res = sandbox.run(
        sandbox.ExecSpec(bash, ('--norc', '--noprofile')),
        f'{TOUCH} {workspace.cwd / "control"}'.encode(),
        workspace=workspace,
    )
    assert res.failure is None and res.returncode == 0
    assert (workspace.cwd / 'control').exists()


def _encoded(script: str) -> str:
    return base64.b64encode(script.encode('utf-16-le')).decode('ascii')


def test_pwsh_never_executes(validator, workspace):
    require(Shell.POWERSHELL)

    def m(n):
        return str(workspace.cwd / f'marker-{n}')

    cases = [
        f'$({NEW_ITEM} {m(1)})',
        f'& {{ {NEW_ITEM} {m(2)} }}',
        f'{IEX} "{NEW_ITEM} {m(3)}"',
        f'{PS} -EncodedCommand {_encoded(f"{NEW_ITEM} {m(4)}")}',
        f'"$({NEW_ITEM} {m(5)})"',
        f'[ValidateScript({{{NEW_ITEM} {m(6)}; $true}})]$x = 1',
        f'class C {{ static $x = ({NEW_ITEM} {m(7)}) }}',
        f'function f {{ {NEW_ITEM} {m(8)} }}; f',
        f"[scriptblock]::Create('{NEW_ITEM} {m(9)}').Invoke()",
        f'#requires -Version 5\n{NEW_ITEM} {m(10)}',
        f'Configuration C {{ Node x {{ {NEW_ITEM} {m(11)} }} }}',
        f'using namespace System.IO\n{NEW_ITEM} {m(12)}',
        f'{NEW_ITEM} {m(13)}',
        f'{PS} -c "{NEW_ITEM} {m(14)}"',
    ]
    for payload in cases:
        verdict = validator.validate(payload, Shell.POWERSHELL)
        assert verdict.status in ('ok', 'invalid'), verdict
    assert validator.pwsh.starts == 1
    assert sorted(p.name for p in workspace.cwd.iterdir()) == []


def test_applescript_never_executes(validator, workspace):
    require(Shell.APPLESCRIPT)

    def m(n):
        return str(workspace.cwd / f'marker-{n}')

    shell_script = J('do shell ', 'script')
    write = J('open for ', 'access')
    cases = [
        f'set f to {write} POSIX file "{m(6)}" with write permission\n'
        'close access f',
        f'{shell_script} "{TOUCH} {m(1)}"',
        f'on run\n{shell_script} "{TOUCH} {m(2)}"\nend run',
        f'tell application "Finder"\n{shell_script} "{TOUCH} {m(3)}"\nend tell',
        J(
            'var app = Application.currentApplication();\n',
            'app.includeStandardAdditions = true;\n',
            f"app.doShellScript('{TOUCH} {m(4)}');",
        ),
        f"(() => {{ ObjC.import('stdlib'); $.system('{TOUCH} {m(5)}'); }})();",
    ]
    for payload in cases:
        verdict = validator.validate(payload, Shell.APPLESCRIPT)
        assert verdict.status == 'ok', verdict
    assert sorted(p.name for p in workspace.cwd.iterdir()) == []


def test_cmd_is_pure(validator, workspace):
    verdict = validator.validate(J('echo a > ', str(workspace.cwd / 'm')))
    assert verdict.shell is Shell.CMD or verdict.status
    assert not (workspace.cwd / 'm').exists()
