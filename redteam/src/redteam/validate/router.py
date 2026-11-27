"""Pick the shell a payload is written for (S8 §1, "router").

A parser saying "ok" only means something for the right shell: pwsh accepts
most cmd and bash lines, ``bash -n`` accepts most cmd lines. So when the
caller does not know the shell, this scores cheap lexical cues per shell and
picks the best one.

Mixed payloads (``cmd /c powershell -enc ...``) route to the *outer* shell;
``recurse`` then extracts and validates the inner scripts.
"""

from __future__ import annotations

import re

from redteam.models import Shell

_SHEBANG = re.compile(r'\A#!\s*\S*?(?:/env\s+)?(bash|zsh|sh|dash|pwsh)\b')

# (pattern, weight) per shell. Patterns are case-insensitive.
_CUES: dict[Shell, tuple[tuple[str, int], ...]] = {
    Shell.APPLESCRIPT: (
        (r'^\s*tell\s+(application|app)\b', 6),
        (r'^\s*end\s+tell\b', 6),
        (r'\bdo\s+shell\s+script\b', 6),
        (r'^\s*display\s+(dialog|notification|alert)\b', 5),
        (r'^\s*on\s+run\b', 4),
        (r'^\s*set\s+\w+\s+to\b', 3),
        (r'\bObjC\.import\b|\bApplication\s*\(\s*[\'"]', 6),
    ),
    Shell.CMD: (
        (r'^\s*@?(cmd|cmd\.exe)\b', 5),
        (r'(?:^|[\s"&|(])[a-z]:\\', 2),
        (r'%[a-z_][\w]*(:[^%\n]*)?%', 3),
        (r'%~?[dpnx]*[0-9]\b|%%[a-z]\b', 3),
        (r'\w\^\w', 3),
        (r'^\s*@?echo\s+off\b', 5),
        (r'^\s*@?(set|setlocal|endlocal|goto|call|start|rem)\b', 3),
        (
            r'^\s*@?(mshta|rundll32|regsvr32|certutil|bitsadmin|conhost'
            r'|wscript|cscript|forfiles|msiexec)(\.exe)?\b',
            4,
        ),
        (r'\bif\s+(not\s+)?(exist|defined|errorlevel)\b', 4),
        (r'\bfor\s+(/[dlrf]\s+)?%%?[a-z]\s+in\s*\(', 5),
        (r'\s/[a-z]\b', 1),
        (r'>\s*nul\b', 3),
        (r'\.(bat|cmd)\b', 2),
    ),
    Shell.POWERSHELL: (
        (r'^\s*(&\s*)?(powershell|pwsh)(\.exe)?\b', 3),
        (
            r'\b(get|set|new|invoke|start|add|remove|write|out|convertto'
            r'|convertfrom|select|where|foreach|test|import|export)-[a-z]+\b',
            4,
        ),
        (r'\b(iex|iwr|irm)\b', 3),
        (r'\$env:\w+', 4),
        (r'\$[a-z_]\w*\s*=', 2),
        (r'\[(system\.)?[a-z]+(\.[a-z]+)*\]::', 5),
        (r'\[(char|string|int|byte|convert|text\.encoding|scriptblock)\]', 4),
        (
            r'\s-(encodedcommand|enc|ec|e|nop|noprofile|w|windowstyle'
            r'|executionpolicy|ep|c|command)\s',
            1,
        ),
        (r'-(join|split|replace|f|bxor|band)\b', 2),
        (r'\|\s*%\s*\{|\|\s*\?\s*\{', 3),
        (r'`[a-z$"]', 1),
        (r'\$\(\s*[a-z]+-[a-z]+', 3),
    ),
    Shell.BASH: (
        (r'^\s*(sudo\s+)?(curl|wget)\b.*\|\s*(ba|z|)sh\b', 4),
        (r'\|\s*(sudo\s+)?(bash|sh|zsh)\b', 3),
        (r'\$\{[a-z_#!]\w*([:#%/^,][^}]*)?\}', 2),
        (r'\$\(\s*[a-z]', 1),
        (r'\[\[.*\]\]', 3),
        (r'<\(', 3),
        (r'\$\'', 2),
        (r'\b(export|chmod|nohup|xattr|osascript|launchctl|source)\b', 3),
        (r'\bbase64\s+(-d|--decode|-D)\b', 3),
        (r'/dev/(tcp|udp)/', 4),
        (r'^\s*(bash|sh|zsh)\s+-c\b', 2),
        (r'(?:^|\s)~/|/tmp/|/usr/(local/)?bin/', 2),
        (r'\bfi\b|\bdone\b|\besac\b', 3),
        (r';\s*then\b|;\s*do\b', 3),
        (r'\beval\s+["\'$]', 2),
    ),
}
_COMPILED = {
    shell: tuple(
        (re.compile(p, re.IGNORECASE | re.MULTILINE), w) for p, w in cues
    )
    for shell, cues in _CUES.items()
}
_ZSH_ONLY = re.compile(r'\(\s*[eN.@/]+[^)]*\)\s*$|\$\{\(\w+\)|=\(', re.M)
_BASH_ONLY = re.compile(r'\[\[|<\(|\$\'|\bfunction\s+\w+|\blocal\b|\bdeclare\b')
# Order used to break ties: outer launchers first, then the rest.
_TIE_ORDER = (
    Shell.APPLESCRIPT,
    Shell.CMD,
    Shell.POWERSHELL,
    Shell.BASH,
)


def scores(payload: str) -> dict[Shell, int]:
    text = payload[:65536]
    return {
        shell: sum(w * min(3, len(rx.findall(text))) for rx, w in cues)
        for shell, cues in _COMPILED.items()
    }


def route(payload: str) -> Shell:
    """Best guess of the payload's shell (BASH when nothing matches)."""
    m = _SHEBANG.match(payload)
    if m:
        name = m.group(1)
        return {
            'bash': Shell.BASH,
            'zsh': Shell.ZSH,
            'sh': Shell.SH,
            'dash': Shell.SH,
            'pwsh': Shell.POWERSHELL,
        }[name]
    s = scores(payload)
    best = max(_TIE_ORDER, key=lambda sh: (s[sh], -_TIE_ORDER.index(sh)))
    if (
        (best is Shell.BASH or s[best] == 0)
        and _ZSH_ONLY.search(payload)
        and not (_BASH_ONLY.search(payload))
    ):
        return Shell.ZSH
    if s[best] == 0:
        return Shell.BASH
    return best
