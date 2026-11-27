"""Static guards for docs/plan/phase-5.md §5.3.4 and §5.5.3.

Payloads are never executed or put on a clipboard, and nothing in the
orchestrator can merge a pull request. These checks scan the source so a
regression fails CI even if no test exercises the offending path.
"""

import re
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / 'src' / 'redteam'

FORBIDDEN = {
    r'shell\s*=\s*True': 'shell=True',
    r'\bos\.system\b': 'os.system',
    r'\bos\.popen\b': 'os.popen',
    r'\bpyperclip\b': 'clipboard library',
    r'\b(pbcopy|xclip|xsel|wl-copy|clip\.exe)\b': 'clipboard command',
    r'gh\s+pr\s+merge|[\'"]merge[\'"]\s*[,\]]': 'PR merge',
    r'push\s+origin\s+(dev|main)\b': 'push to dev/main',
}

# Only these may start processes (validators, engine builds, the blue run).
SUBPROCESS_ALLOWED = ('validate/sandbox.py', 'engine.py', 'blue/')


def _sources():
    return sorted(p for p in SRC.rglob('*.py'))


def test_no_forbidden_calls():
    hits = []
    for path in _sources():
        text = path.read_text(encoding='utf-8')
        for pattern, label in FORBIDDEN.items():
            if re.search(pattern, text):
                hits.append(f'{path.relative_to(SRC)}: {label}')
    assert not hits, hits


def test_subprocess_only_where_allowed():
    hits = []
    for path in _sources():
        rel = path.relative_to(SRC).as_posix()
        if rel.startswith(SUBPROCESS_ALLOWED):
            continue
        text = path.read_text(encoding='utf-8')
        if re.search(r'\bsubprocess\b|\bos\.exec|\bos\.spawn|\bpty\b', text):
            hits.append(rel)
    assert not hits, hits


def test_cli_refuses_windows():
    from redteam.cli import refuse_windows

    assert refuse_windows('win32')
    assert refuse_windows('darwin') is None
    assert refuse_windows('linux') is None
