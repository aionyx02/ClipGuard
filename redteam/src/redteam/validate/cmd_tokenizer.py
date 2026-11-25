"""Structural checker for cmd.exe input (S8 §3 items 1-3).

cmd.exe has no parse-only mode and is very lenient, so "valid" here means
"structurally sound": operators have commands on both sides, redirections
have targets, parentheses balance, and ``if`` / ``for`` have their basic
shape. Variables are recognised (so ``%x:a=&%`` does not look like an
operator) but never substituted.

Pure functions only: no IO, no processes. Positions are 1-based line and
column in characters of the original input.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from redteam.models import SyntaxIssue

# Token kinds.
WORD = 'word'
OP = 'op'  # & && | ||
REDIR = 'redir'  # > >> < 2> 2>&1 ...
LPAREN = 'lparen'
RPAREN = 'rparen'
NEWLINE = 'newline'
EOF = 'eof'

BINARY_OPS = ('|', '&&', '||')
IF_UNARY = ('exist', 'defined', 'errorlevel', 'cmdextversion')
IF_COMPARE = ('equ', 'neq', 'lss', 'leq', 'gtr', 'geq')
FOR_OPTS = ('/d', '/r', '/l', '/f')

# Variable references, matched at '%' whether or not inside quotes (percent
# expansion runs before quotes are seen).
_PCT_VAR = re.compile(
    r"""
    %%~[fdpnxsatz]*(?:\$[^:%\n]+:)?[A-Za-z]   # %%~dpi, %%~$PATH:i
  | %%[A-Za-z0-9]                             # %%i
  | %~[fdpnxsatz]*(?:\$[^:%\n]+:)?[0-9]       # %~dp0, %~$PATH:1
  | %[0-9*]                                   # %1, %*
  | %[A-Za-z_][\w#$'()*+,.?@\[\]`{}~-]*       # %name
      (?::(?:~-?\d+(?:,-?\d+)?                #   :~a,b
            |\*?[^%=\n]*=[^%\n]*))?           #   :x=y / :*x=y
    %
    """,
    re.VERBOSE,
)
_BANG_VAR = re.compile(r'![A-Za-z_][\w#$.~:,=*-]*!')
_FOR_VAR = re.compile(r'%%?[A-Za-z]')
_DELIMS = ' \t'


@dataclass(frozen=True)
class Token:
    kind: str
    text: str
    start: int
    # REDIR only: True for handle duplication like 2>&1 (no target needed).
    dup: bool = False
    # WORD only: variable references found while lexing (for tests/recurse).
    variables: tuple[str, ...] = ()


@dataclass(frozen=True)
class Command:
    """A simple command: its words with carets removed, quotes kept."""

    words: tuple[str, ...]
    start: int


@dataclass(frozen=True)
class CmdParse:
    issues: tuple[SyntaxIssue, ...]
    commands: tuple[Command, ...]
    # Not errors (cmd tolerates them), e.g. an unclosed quote.
    warnings: tuple[SyntaxIssue, ...] = field(default=())

    @property
    def ok(self) -> bool:
        return not self.issues


def _position(src: str, offset: int) -> tuple[int, int]:
    line = src.count('\n', 0, offset) + 1
    col = offset - (src.rfind('\n', 0, offset) + 1) + 1
    return line, col


def tokenize(src: str) -> tuple[list[Token], list[int]]:
    """Return tokens and the offsets of unclosed quotes (warnings)."""
    tokens: list[Token] = []
    unclosed: list[int] = []
    n = len(src)
    i = 0
    buf: list[str] = []
    variables: list[str] = []
    word_start = -1
    in_quote = False
    quote_start = 0

    def flush() -> None:
        nonlocal buf, variables, word_start
        if word_start >= 0:
            tokens.append(
                Token(
                    WORD, ''.join(buf), word_start, variables=tuple(variables)
                )
            )
        buf = []
        variables = []
        word_start = -1

    def add(ch: str, at: int) -> None:
        nonlocal word_start
        if word_start < 0:
            word_start = at
        buf.append(ch)

    while i < n:
        c = src[i]
        if c == '%':
            m = _PCT_VAR.match(src, i)
            if m:
                for ch in m.group():
                    add(ch, i)
                variables.append(m.group())
                i = m.end()
                continue
            add(c, i)
            i += 1
            continue
        if c == '\r' and i + 1 < n and src[i + 1] == '\n':
            i += 1
            continue
        if c == '\n':
            if in_quote:
                unclosed.append(quote_start)
                in_quote = False
            flush()
            tokens.append(Token(NEWLINE, '\n', i))
            i += 1
            continue
        if in_quote:
            add(c, i)
            if c == '"':
                in_quote = False
            i += 1
            continue
        if c == '"':
            in_quote = True
            quote_start = i
            add(c, i)
            i += 1
            continue
        if c == '^':
            nxt = src[i + 1] if i + 1 < n else ''
            if nxt == '\r' and i + 2 < n and src[i + 2] == '\n':
                i += 1
                nxt = '\n'
            if nxt == '\n':
                # Line continuation: the first char of the next line is
                # taken literally.
                i += 2
                if i < n and src[i] not in '\r\n':
                    add(src[i], i)
                    i += 1
                continue
            if nxt == '':
                i += 1
                continue
            add(nxt, i)
            i += 2
            continue
        if c == '!':
            m = _BANG_VAR.match(src, i)
            if m:
                for ch in m.group():
                    add(ch, i)
                variables.append(m.group())
                i = m.end()
                continue
        if c in _DELIMS:
            flush()
            i += 1
            continue
        if c in '&|':
            flush()
            if i + 1 < n and src[i + 1] == c:
                tokens.append(Token(OP, c * 2, i))
                i += 2
            else:
                tokens.append(Token(OP, c, i))
                i += 1
            continue
        if c in '<>':
            # A single digit directly before > / < is the handle number,
            # but only if it is a token on its own (`echo a2>x` keeps 2).
            start = i
            handle = ''
            if word_start >= 0 and len(buf) == 1 and buf[0].isdigit():
                handle = buf[0]
                start = word_start
                buf = []
                variables = []
                word_start = -1
            flush()
            op = c
            i += 1
            if c == '>' and i < n and src[i] == '>':
                op = '>>'
                i += 1
            dup = False
            if i < n and src[i] == '&':
                dup = True
                op += '&'
                i += 1
                if i < n and src[i].isdigit():
                    op += src[i]
                    i += 1
                else:
                    op += '?'  # invalid handle; reported by the parser
            tokens.append(Token(REDIR, handle + op, start, dup=dup))
            continue
        if c == '(':
            if word_start < 0:
                tokens.append(Token(LPAREN, '(', i))
            else:
                add(c, i)
            i += 1
            continue
        if c == ')':
            flush()
            tokens.append(Token(RPAREN, ')', i))
            i += 1
            continue
        add(c, i)
        i += 1
    if in_quote:
        unclosed.append(quote_start)
    flush()
    tokens.append(Token(EOF, '', n))
    return tokens, unclosed


class _Parser:
    def __init__(self, src: str, tokens: list[Token]) -> None:
        self.src = src
        self.toks = tokens
        self.i = 0
        self.issues: list[SyntaxIssue] = []
        self.commands: list[Command] = []

    # -- helpers ---------------------------------------------------------

    def peek(self, k: int = 0) -> Token:
        return self.toks[min(self.i + k, len(self.toks) - 1)]

    def next(self) -> Token:
        tok = self.peek()
        if tok.kind != EOF:
            self.i += 1
        return tok

    def issue(self, issue_id: str, tok: Token) -> None:
        line, col = _position(self.src, tok.start)
        self.issues.append(SyntaxIssue(id=issue_id, line=line, column=col))

    def is_word(self, *values: str) -> bool:
        tok = self.peek()
        return tok.kind == WORD and (not values or tok.text.lower() in values)

    def at_command_end(self, depth: int) -> bool:
        tok = self.peek()
        return tok.kind in (OP, NEWLINE, EOF) or (
            tok.kind == RPAREN and depth > 0
        )

    # -- grammar ---------------------------------------------------------

    def sequence(self, depth: int) -> None:
        """Commands joined by operators/newlines, until EOF or ')'."""
        # start | newline | lparen | operator text | cmd
        last = 'lparen' if depth > 0 else 'start'
        last_tok = self.peek()
        while True:
            tok = self.peek()
            if tok.kind == EOF or (tok.kind == RPAREN and depth > 0):
                if last in BINARY_OPS:
                    self.issue('cmd.dangling-operator', last_tok)
                if tok.kind == RPAREN and last == 'lparen':
                    self.issue('cmd.empty-block', tok)
                return
            if tok.kind == NEWLINE:
                if last in BINARY_OPS:
                    self.issue('cmd.dangling-operator', last_tok)
                self.next()
                if last != 'lparen':
                    last = 'newline'
                continue
            if tok.kind == OP:
                if last in ('start', 'newline', 'lparen'):
                    self.issue('cmd.leading-operator', tok)
                elif last in ('&', *BINARY_OPS):
                    self.issue('cmd.doubled-operator', tok)
                self.next()
                last = tok.text
                last_tok = tok
                continue
            self.command(depth)
            last = 'cmd'

    def redirect(self, depth: int) -> None:
        tok = self.next()
        if tok.dup:
            if tok.text.endswith('?'):
                self.issue('cmd.redirect-bad-handle', tok)
            return
        target = self.peek()
        if target.kind == WORD or (target.kind == RPAREN and depth == 0):
            self.next()
            return
        self.issue('cmd.redirect-missing-target', tok)

    def trailing_redirects(self, depth: int) -> None:
        while self.peek().kind == REDIR:
            self.redirect(depth)

    def command(self, depth: int) -> None:
        tok = self.peek()
        if tok.kind == REDIR:
            # Redirection before the command name: `>out echo a`.
            self.redirect(depth)
            if not self.at_command_end(depth):
                self.command(depth)
            return
        if tok.kind == LPAREN:
            self.block(depth)
            self.trailing_redirects(depth)
            return
        if tok.kind == WORD:
            word = tok.text.lstrip('@').lower()
            if word == '' and len(tok.text) > 0:
                self.next()
                if not self.at_command_end(depth):
                    self.command(depth)
                return
            if word.startswith(':') or word == 'rem' or word.startswith('rem.'):
                self.skip_line()
                return
            if word == 'if':
                self.if_command(depth)
                return
            if word == 'for':
                self.for_command(depth)
                return
        self.simple(depth)

    def simple(self, depth: int) -> None:
        start = self.peek().start
        words: list[str] = []
        while True:
            tok = self.peek()
            if tok.kind == WORD:
                words.append(tok.text)
                self.next()
            elif tok.kind == REDIR:
                self.redirect(depth)
            elif tok.kind == LPAREN or (tok.kind == RPAREN and depth == 0):
                words.append(tok.text)
                self.next()
            else:
                break
        if words:
            words[0] = words[0].lstrip('@') or words[0]
            self.commands.append(Command(tuple(words), start))

    def skip_line(self) -> None:
        while self.peek().kind not in (NEWLINE, EOF):
            self.next()

    def block(self, depth: int) -> None:
        open_tok = self.next()  # '('
        self.sequence(depth + 1)
        if self.peek().kind == RPAREN:
            self.next()
        else:
            self.issue('cmd.unclosed-paren', open_tok)

    def body(self, depth: int, missing: str, at: Token) -> bool:
        """The command after if/else/do; returns True if it was a block."""
        if self.at_command_end(depth):
            self.issue(missing, at)
            return False
        if self.peek().kind == LPAREN:
            self.block(depth)
            self.trailing_redirects(depth)
            return True
        self.command(depth)
        return False

    def if_command(self, depth: int) -> None:
        if_tok = self.next()
        if self.is_word('/i'):
            self.next()
        if self.is_word('not'):
            self.next()
        if not self.condition(depth):
            self.issue('cmd.if-missing-condition', if_tok)
            return
        was_block = self.body(depth, 'cmd.if-missing-command', if_tok)
        if was_block and self.is_word('else'):
            else_tok = self.next()
            self.body(depth, 'cmd.else-missing-command', else_tok)

    def condition(self, depth: int) -> bool:
        if not self.is_word():
            return False
        first = self.next()
        low = first.text.lower()
        if low in IF_UNARY:
            if not self.is_word():
                return False
            self.next()
            return True
        if '==' in first.text:
            left, _, right = first.text.partition('==')
            if right:
                return True
            if not self.is_word():
                return False
            self.next()
            return True
        if not self.is_word():
            return False
        op = self.peek()
        if op.text.lower() in IF_COMPARE or op.text == '==':
            self.next()
            if not self.is_word():
                return False
            self.next()
            return True
        if op.text.startswith('=='):
            self.next()
            if len(op.text) > 2:
                return True
            if not self.is_word():
                return False
            self.next()
            return True
        return False

    def for_command(self, depth: int) -> None:
        for_tok = self.next()
        while self.is_word(*FOR_OPTS):
            opt = self.next().text.lower()
            nxt = self.peek()
            if (
                opt in ('/r', '/f')
                and nxt.kind == WORD
                and not _FOR_VAR.fullmatch(nxt.text)
            ):
                self.next()  # /r root path or /f "options"
        if not (self.is_word() and _FOR_VAR.fullmatch(self.peek().text)):
            self.issue('cmd.for-missing-variable', for_tok)
            return
        self.next()
        if not self.is_word('in'):
            self.issue('cmd.for-missing-in', for_tok)
            return
        self.next()
        if self.peek().kind != LPAREN:
            self.issue('cmd.for-missing-set', for_tok)
            return
        open_tok = self.next()
        while self.peek().kind not in (RPAREN, EOF):
            self.next()
        if self.peek().kind != RPAREN:
            self.issue('cmd.unclosed-paren', open_tok)
            return
        self.next()
        if not self.is_word('do'):
            self.issue('cmd.for-missing-do', for_tok)
            return
        do_tok = self.next()
        self.body(depth, 'cmd.for-missing-command', do_tok)

    def script(self) -> None:
        # At depth 0 a stray ')' is literal text, so this consumes all.
        self.sequence(0)


def parse(src: str) -> CmdParse:
    tokens, unclosed = tokenize(src)
    parser = _Parser(src, tokens)
    parser.script()
    warnings = tuple(
        SyntaxIssue(id='cmd.unclosed-quote', line=pos[0], column=pos[1])
        for pos in (_position(src, off) for off in unclosed)
    )
    return CmdParse(
        issues=tuple(parser.issues),
        commands=tuple(parser.commands),
        warnings=warnings,
    )


def check(src: str) -> tuple[SyntaxIssue, ...]:
    """Structural errors only (empty tuple = structurally ok)."""
    return parse(src).issues
