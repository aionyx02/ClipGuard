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


def test_blue_files_feed_the_report(tmp_path):
    import json as _json

    from redteam import cli

    cli.write_judgments(
        tmp_path, 2, {'v1': 'equivalent', 'v2': 'not_equivalent'}
    )
    stored = _json.loads((tmp_path / 'blue-r2-judgments.json').read_text())
    assert stored == {
        'round': 2,
        'judgments': {'v1': 'equivalent', 'v2': 'not_equivalent'},
    }
    (tmp_path / 'blue-r2-summary.json').write_text(
        _json.dumps(
            {
                'ok': True,
                'pr': 'https://example.invalid/pr/1',
                'rules_lines': 36,
                'cases_added': 10,
                'heldout_p99_us': 581,
                'minutes': 16.1,
                'tool_calls': 54,
                'models': ['a', 'b'],
            }
        )
    )
    cost, eq = cli.read_blue(tmp_path, 2)
    assert eq == {'v1': 'equivalent', 'v2': 'not_equivalent'}
    assert (cost.rules_lines_changed, cost.corpus_cases_added) == (36, 10)
    assert (cost.blue_turns, cost.model, cost.heldout_p99_us) == (54, 'b', 581)
    # A failed round is no PR and costs nothing; missing files are fine.
    (tmp_path / 'blue-r2-summary.json').write_text('{"ok": false}')
    assert cli.read_blue(tmp_path, 2)[0] is None
    assert cli.read_blue(tmp_path, 9) == (None, {})
