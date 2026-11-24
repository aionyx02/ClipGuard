# Type stubs for the native module (crates/py/src/lib.rs). The dicts follow the
# Report JSON of docs/plan/phase-2.md §2.2 (TS: packages/core-js/src/types.ts).
from typing import Any

ENGINE_VERSION: str
__version__: str

def analyze(
    text: str, locale: str = 'zh-TW', *, packs: list[str] | None = None
) -> dict[str, Any]: ...
def mask(text: str, locale: str = 'zh-TW') -> str: ...
def deobfuscate(text: str, locale: str = 'zh-TW') -> dict[str, Any]: ...
