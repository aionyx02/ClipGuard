import pytest

from redteam import cli
from redteam.models import Shell, SyntaxIssue, SyntaxVerdict


def _v(status, *ids):
    return SyntaxVerdict(
        shell=Shell.CMD,
        status=status,
        errors=tuple(SyntaxIssue(id=i) for i in ids),
    )


def test_oversized_padding_is_unchecked_not_crash():
    out = cli.unchecked_if_too_large(_v('validator_crash', 'payload-too-large'))
    assert out.status == 'unchecked' and out.errors == ()
    assert cli.usable_syntax(out)
    # Any other crash stays a crash (never counted as valid).
    other = _v('validator_crash', 'no-sandbox')
    assert cli.unchecked_if_too_large(other).status == 'validator_crash'
    mixed = _v('validator_crash', 'payload-too-large', 'timeout')
    assert cli.unchecked_if_too_large(mixed).status == 'validator_crash'
    assert not cli.usable_syntax(_v('invalid', 'x'))


def test_parser_covers_every_subcommand():
    p = cli.build_parser()
    assert set(cli.HANDLERS) == set(cli.SUBCOMMANDS)
    a = p.parse_args(['attack', '--run-id', 'r1', '--round', '2'])
    assert a.split == 'train' and a.rev == 'HEAD'
    b = p.parse_args(['blue', '--run-id', 'r1', '--round', '1'])
    assert b.open_pr is False and b.base == 'feature/phase-5-agent'
    with pytest.raises(SystemExit):
        p.parse_args(['report', '--out', 'x'])  # --version is required


def test_main_refuses_windows(monkeypatch, capsys):
    monkeypatch.setattr(cli.sys, 'platform', 'win32')
    assert cli.main(['seeds']) == 3
