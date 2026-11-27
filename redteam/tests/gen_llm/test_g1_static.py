"""gen_llm never starts processes, prints or logs (phase-5.md §5.3.4)."""

import re
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / 'src' / 'redteam' / 'gen_llm'

PATTERNS = {
    r'\bsubprocess\b|\bos\.(exec|spawn|system|popen)': 'process',
    r'\bprint\s*\(': 'print',
    r'\blogging\b|\blogger\b': 'logging',
    r'\bsys\.(stdout|stderr)\b': 'stdout',
    r'\bopen\s*\(|\.write_text\(|\.write_bytes\(': 'file write',
    r'["\']tools["\']\s*:': 'tools in request',
}


def test_gen_llm_sources_are_clean():
    files = sorted(SRC.rglob('*.py'))
    assert files
    hits = []
    for path in files:
        text = path.read_text(encoding='utf-8')
        for pattern, label in PATTERNS.items():
            if re.search(pattern, text):
                hits.append(f'{path.name}: {label}')
    assert not hits, hits
