"""``redteam`` command line (docs/plan/phase-5.md §5.3.1).

Subcommands are wired up as the workstreams land; for now this only enforces
the platform rule from §5.3.4.
"""

from __future__ import annotations

import argparse
import sys

SUBCOMMANDS = (
    'seeds',
    'generate',
    'validate',
    'eval',
    'blue',
    'report',
    'loop',
)


def refuse_windows(platform: str = sys.platform) -> str | None:
    """S8: on Windows, a UNC `using module` may reach SMB at parse time."""
    if platform.startswith('win'):
        return 'redteam runs on macOS or Linux only (phase-5.md §5.3.4)'
    return None


def main(argv: list[str] | None = None) -> int:
    reason = refuse_windows()
    if reason:
        print(reason, file=sys.stderr)
        return 3
    parser = argparse.ArgumentParser(prog='redteam')
    parser.add_argument('command', choices=SUBCOMMANDS)
    args = parser.parse_args(argv)
    print(f'redteam {args.command}: not implemented yet', file=sys.stderr)
    return 3
