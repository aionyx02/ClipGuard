"""cmd.exe structural checker (S8 §3 items 1-3). Pure: no processes."""

import pytest

from redteam.validate import cmd_tokenizer as ct


def J(*parts: str) -> str:
    # Command-like strings are assembled at runtime (Defender, CLAUDE.md).
    return ''.join(parts)


PS = J('power', 'shell')
CURL = J('cu', 'rl')

# --- the 11 cases from S8 §3 (prototype cmdtok.py) ----------------------
S8_CASES = [
    ('echo hi |', ['cmd.dangling-operator']),
    ('&& echo x', ['cmd.leading-operator']),
    ('if 1==1 (echo a) else (echo b', ['cmd.unclosed-paren']),
    ('for %%i in (a b) echo %%i', ['cmd.for-missing-do']),
    (J('c^u^r^l', ' https://example.invalid/x'), []),
    ('echo %COMSPEC:~-16,1%', []),
    ('dir 2>&1 >nul | more', []),
    (J('cmd /c echo hi ^& del x & ', PS, ' -c Get-Date'), []),
    ('set x=%PATH% && echo !x! | findstr a > nul', []),
    ('if exist a.txt (echo a) else (echo b)', []),
    ('for %%i in (a b) do echo %%i', []),
]

# --- good (structurally sound) -----------------------------------------
GOOD = [
    'echo hello',
    '@echo off',
    'echo a & echo b',
    'echo a && echo b || echo c',
    'echo a &',  # trailing single & is accepted by cmd
    'type a.txt | find "x" | sort',
    'echo a > out.txt',
    'echo a >> out.txt',
    'sort < in.txt > out.txt',
    'echo a 1>nul 2>nul',
    'echo a 2>&1',
    '>out.txt echo a',
    'echo "a & b | c"',
    'echo a ^& b ^| c',
    'echo a ^> b',
    'echo 50%% done',
    'echo %USERPROFILE%\\x',
    'echo %PATH:;= %',
    'echo %x:a=&%',  # the & is inside the substitution
    'echo %~dp0 %1 %*',
    'echo !x:a=b!',
    'echo a^\nb',  # line continuation
    'echo a\necho b',
    'echo a\r\necho b\r\n',
    '(echo a)',
    '(echo a & echo b) > out.txt',
    '(\necho a\necho b\n)',
    'if not exist x mkdir x',
    'if defined x echo %x%',
    'if errorlevel 1 exit /b 1',
    'if %errorlevel% neq 0 exit /b 1',
    'if /i "%a%"=="yes" (echo y) else (echo n)',
    'if "%a%" == "b" echo same',
    'if 1 EQU 1 echo eq',
    'for /l %%i in (1,1,5) do echo %%i',
    'for /f "tokens=1,2 delims=," %%a in (data.csv) do echo %%a %%b',
    'for /r C:\\tmp %%f in (*.txt) do echo %%f',
    'for /d %%d in (*) do (echo %%d)',
    'for %i in (a) do echo %i',
    ':label',
    ':: a comment & more | text',
    'rem a comment & more | text',
    'goto :eof',
    'call :sub arg1',
    'echo )',  # ')' outside a block is literal
    'echo a(b)c',
    'start "" notepad.exe',
    J(PS, ' -nop -w hidden -c "Get-Date"'),
    J('cmd /c "echo a && echo b"'),
    J(CURL, ' -o x.txt https://example.invalid/a & type x.txt'),
    'echo "unclosed quote & still fine',
    'echo a^',  # caret at EOF is ignored
]

# --- bad (structural errors) -------------------------------------------
BAD = [
    ('| echo a', 'cmd.leading-operator'),
    ('& echo a', 'cmd.leading-operator'),
    ('|| echo a', 'cmd.leading-operator'),
    ('echo a & & echo b', 'cmd.doubled-operator'),
    ('echo a | | echo b', 'cmd.doubled-operator'),
    ('echo a && | echo b', 'cmd.doubled-operator'),
    ('echo a &&& echo b', 'cmd.doubled-operator'),
    ('echo a ||', 'cmd.dangling-operator'),
    ('echo a &&', 'cmd.dangling-operator'),
    ('echo a |\necho b', 'cmd.dangling-operator'),
    ('(echo a |)', 'cmd.dangling-operator'),
    ('echo a >', 'cmd.redirect-missing-target'),
    ('echo a >> & echo b', 'cmd.redirect-missing-target'),
    ('sort <', 'cmd.redirect-missing-target'),
    ('echo a 2>', 'cmd.redirect-missing-target'),
    ('echo a > | more', 'cmd.redirect-missing-target'),
    ('echo a 2>&', 'cmd.redirect-bad-handle'),
    ('(echo a', 'cmd.unclosed-paren'),
    ('(echo a & (echo b)', 'cmd.unclosed-paren'),
    ('()', 'cmd.empty-block'),
    ('if', 'cmd.if-missing-condition'),
    ('if exist', 'cmd.if-missing-condition'),
    ('if a== ', 'cmd.if-missing-condition'),
    ('if a b echo x', 'cmd.if-missing-condition'),
    ('if exist x', 'cmd.if-missing-command'),
    ('if 1==1 (echo a) else', 'cmd.else-missing-command'),
    ('for in (a) do echo a', 'cmd.for-missing-variable'),
    ('for %%i (a) do echo a', 'cmd.for-missing-in'),
    ('for %%i in a do echo a', 'cmd.for-missing-set'),
    ('for %%i in (a b do echo a', 'cmd.unclosed-paren'),
    ('for %%i in (a) do', 'cmd.for-missing-command'),
    ('for /f "delims=" %%i in (x) echo', 'cmd.for-missing-do'),
    ('echo ok\n| more', 'cmd.leading-operator'),
]


@pytest.mark.parametrize(('src', 'expected'), S8_CASES)
def test_s8_cases(src, expected):
    assert [i.id for i in ct.check(src)] == expected


@pytest.mark.parametrize('src', GOOD)
def test_good(src):
    assert ct.check(src) == ()


@pytest.mark.parametrize(('src', 'issue'), BAD)
def test_bad(src, issue):
    ids = [i.id for i in ct.check(src)]
    assert issue in ids, ids


def test_case_counts():
    assert len(S8_CASES) == 11
    assert len(GOOD) + len(BAD) >= 40


def test_positions_are_one_based_line_and_column():
    (issue,) = ct.check('echo a\necho b |')
    assert issue.id == 'cmd.dangling-operator'
    assert (issue.line, issue.column) == (2, 8)
    (issue,) = ct.check('echo a\n  && echo b')
    assert (issue.line, issue.column) == (2, 3)


def test_variables_recognised_not_substituted():
    tokens, _ = ct.tokenize('echo %A:~1,2% %%i %~dp0 !B! %X:a=&%')
    words = [t for t in tokens if t.kind == ct.WORD]
    found = [v for w in words for v in w.variables]
    assert found == ['%A:~1,2%', '%%i', '%~dp0', '!B!', '%X:a=&%']
    # No substitution: the words keep the raw references.
    assert words[1].text == '%A:~1,2%'


def test_carets_removed_outside_quotes_only():
    parsed = ct.parse('e^c^h^o "a^b" c^&d')
    assert parsed.commands[0].words == ('echo', '"a^b"', 'c&d')


def test_unclosed_quote_is_warning_not_error():
    parsed = ct.parse('echo "abc')
    assert parsed.ok
    assert [w.id for w in parsed.warnings] == ['cmd.unclosed-quote']


def test_commands_split_on_operators():
    parsed = ct.parse(J('cmd /c "echo a" & ', PS, ' -c x | more'))
    assert [c.words[0] for c in parsed.commands] == ['cmd', PS, 'more']


def test_never_raises_on_odd_input():
    for src in ['', '^', '%', '%%', '"', '(((', ')))', '\x00&\x00', '>' * 50]:
        ct.parse(src)
