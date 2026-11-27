"""Runs the JS policy tests for the blue-team opencode plugin (§5.5.1)."""

import shutil
import subprocess
from pathlib import Path

import pytest

TEST = Path(__file__).parent / 'blue' / 'policy.test.mjs'


@pytest.mark.skipif(shutil.which('node') is None, reason='node not installed')
def test_blue_policy_js():
    r = subprocess.run(
        ['node', '--test', str(TEST)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert r.returncode == 0, r.stdout[-4000:] + r.stderr[-2000:]
