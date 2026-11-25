"""OpenAI-compatible chat client for G1 (phase-5.md §5.3.3).

Talks to ``/chat/completions`` under ``base_url`` (default: the local Ollama,
``OLLAMA_BASE_URL``) with ``httpx``. Requests never carry ``tools``; output
is constrained with ``response_format: json_schema`` and capped in tokens and
bytes. qwen3 thinking is turned off with ``reasoning_effort: "none"``: on
Ollama 0.40 that is what the OpenAI-compatible endpoint honours (a top-level
``think: false`` is ignored there; it only works on the native ``/api/chat``).

Every result carries what the audit log needs to reproduce the call: model
name and digest, server version, temperature and seed. Response text lives in
``ChatResult.content`` only (excluded from ``repr``); errors carry an error
kind, never request or response text.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from redteam.models import Shell, sha256_hex

DEFAULT_BASE_URL = 'http://127.0.0.1:11434/v1'
DEFAULT_MODEL = 'qwen3.8:27b-mlx'

G1_VARIANTS_PER_CALL = 3
G1_TEMPERATURE = 0.9
# One call returns up to 3 variants; the seeds are at most a few hundred
# characters, so 2k tokens leaves room for heavier obfuscation.
G1_MAX_OUTPUT_TOKENS = 2048
# Local 27B model: ~10-30 s per call; generous so a slow call is not lost.
G1_TIMEOUT_S = 180.0
# Anything bigger is not a well-formed answer to our schema.
G1_MAX_RESPONSE_BYTES = 256 * 1024
# Ollama's OpenAI-compatible way to switch reasoning off (see module doc).
THINKING_OFF: dict[str, Any] = {'reasoning_effort': 'none'}


class G1ClientError(RuntimeError):
    """A failed call. ``kind`` is a short ID; no prompt or response text."""

    def __init__(self, kind: str) -> None:
        super().__init__(kind)
        self.kind = kind


def request_seed(run_seed: int, case_id: str, attempt: int) -> int:
    """Stable per-request sampling seed (phase-5.md §5.9), 31 bits so every
    backend accepts it."""
    key = f'{run_seed}:{case_id}:{attempt}'.encode()
    digest = hashlib.sha256(key).digest()
    return int.from_bytes(digest[:4], 'big') & 0x7FFFFFFF


def output_schema(max_items: int = G1_VARIANTS_PER_CALL) -> dict[str, Any]:
    """JSON schema sent as ``response_format``. ``maxItems`` is enforced by
    Ollama's grammar; there is deliberately no ``maxLength``: a grammar cut
    would silently truncate a payload, so lengths are checked locally."""
    item = {
        'type': 'object',
        'properties': {
            'shell': {'type': 'string', 'enum': [s.value for s in Shell]},
            'payload': {'type': 'string'},
            'technique': {'type': 'string'},
        },
        'required': ['shell', 'payload', 'technique'],
        'additionalProperties': False,
    }
    return {
        'type': 'object',
        'properties': {
            'variants': {
                'type': 'array',
                'items': item,
                'maxItems': max_items,
            }
        },
        'required': ['variants'],
        'additionalProperties': False,
    }


@dataclass(frozen=True)
class ServerInfo:
    model: str
    digest: str | None
    server_version: str | None

    @property
    def model_ref(self) -> str:
        """``name@digest12`` as in the audit log (§5.8)."""
        if self.digest:
            return f'{self.model}@{self.digest[:12]}'
        return self.model


@dataclass(frozen=True)
class ChatResult:
    content: str = field(repr=False)
    info: ServerInfo
    params: dict[str, float | int | str | bool]
    prompt_sha256: str
    response_sha256: str
    latency_ms: int
    tokens_in: int
    tokens_out: int
    finish_reason: str | None


def prompt_hash(messages: list[dict[str, str]]) -> str:
    return sha256_hex(json.dumps(messages, sort_keys=True, ensure_ascii=True))


class ChatClient:
    """Sync client for one model at one OpenAI-compatible endpoint."""

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        base_url: str = DEFAULT_BASE_URL,
        *,
        api_key: str | None = None,
        temperature: float = G1_TEMPERATURE,
        max_tokens: int = G1_MAX_OUTPUT_TOKENS,
        timeout_s: float = G1_TIMEOUT_S,
        max_response_bytes: int = G1_MAX_RESPONSE_BYTES,
        variants_per_call: int = G1_VARIANTS_PER_CALL,
        transport: httpx.BaseTransport | None = None,
        http: httpx.Client | None = None,
    ) -> None:
        self.model = model
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.timeout_s = timeout_s
        self.max_response_bytes = max_response_bytes
        self.variants_per_call = variants_per_call
        self._http = http or httpx.Client(
            transport=transport, timeout=timeout_s, follow_redirects=False
        )
        self._info: ServerInfo | None = None

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> ChatClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def with_model(self, model: str) -> ChatClient:
        """Same endpoint and settings, another model (shares the pool)."""
        return ChatClient(
            model,
            self.base_url,
            api_key=self.api_key,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
            timeout_s=self.timeout_s,
            max_response_bytes=self.max_response_bytes,
            variants_per_call=self.variants_per_call,
            http=self._http,
        )

    # -- server metadata ---------------------------------------------------

    @property
    def _native_root(self) -> str:
        return self.base_url.removesuffix('/v1')

    def _get_json(self, url: str) -> Any:
        try:
            r = self._http.get(url, timeout=10.0)
        except httpx.HTTPError:
            return None
        if r.status_code != 200 or len(r.content) > self.max_response_bytes:
            return None
        try:
            return r.json()
        except ValueError:
            return None

    def info(self) -> ServerInfo:
        """Model digest (``/api/tags``) and Ollama version (``/api/version``).
        Both are ``None`` on servers that are not Ollama."""
        if self._info is None:
            root = self._native_root
            version = self._get_json(f'{root}/api/version')
            tags = self._get_json(f'{root}/api/tags')
            digest = None
            if isinstance(tags, dict):
                for m in tags.get('models') or []:
                    if not isinstance(m, dict):
                        continue
                    names = {m.get('name'), m.get('model')}
                    if self.model in names or f'{self.model}:latest' in names:
                        d = m.get('digest')
                        digest = d if isinstance(d, str) else None
                        break
            server_version = None
            if isinstance(version, dict):
                v = version.get('version')
                server_version = v if isinstance(v, str) else None
            self._info = ServerInfo(self.model, digest, server_version)
        return self._info

    # -- chat ----------------------------------------------------------------

    def request_body(
        self, messages: list[dict[str, str]], seed: int
    ) -> dict[str, Any]:
        """The request JSON. Never contains ``tools`` / ``tool_choice``."""
        return {
            'model': self.model,
            'messages': messages,
            'temperature': self.temperature,
            'seed': seed,
            'max_tokens': self.max_tokens,
            'stream': False,
            'response_format': {
                'type': 'json_schema',
                'json_schema': {
                    'name': 'variants',
                    'strict': True,
                    'schema': output_schema(self.variants_per_call),
                },
            },
            **THINKING_OFF,
        }

    def _post(self, body: dict[str, Any]) -> bytes:
        headers = {'content-type': 'application/json'}
        if self.api_key:
            headers['authorization'] = f'Bearer {self.api_key}'
        data = json.dumps(body, ensure_ascii=True).encode()
        try:
            with self._http.stream(
                'POST',
                f'{self.base_url}/chat/completions',
                content=data,
                headers=headers,
                timeout=self.timeout_s,
            ) as r:
                if r.status_code != 200:
                    raise G1ClientError(f'http-{r.status_code}')
                chunks: list[bytes] = []
                size = 0
                for chunk in r.iter_bytes():
                    size += len(chunk)
                    if size > self.max_response_bytes:
                        raise G1ClientError('response-too-large')
                    chunks.append(chunk)
                return b''.join(chunks)
        except httpx.TimeoutException:
            raise G1ClientError('timeout') from None
        except httpx.HTTPError as e:
            raise G1ClientError(type(e).__name__) from None

    def complete(self, messages: list[dict[str, str]], seed: int) -> ChatResult:
        info = self.info()
        body = self.request_body(messages, seed)
        t0 = time.perf_counter()
        raw = self._post(body)
        latency_ms = int((time.perf_counter() - t0) * 1000)
        try:
            doc = json.loads(raw)
            choice = doc['choices'][0]
            content = choice['message'].get('content') or ''
            finish = choice.get('finish_reason')
            usage = doc.get('usage') or {}
        except (ValueError, KeyError, IndexError, TypeError, AttributeError):
            raise G1ClientError('bad-envelope') from None
        if not isinstance(content, str):
            raise G1ClientError('bad-envelope')
        params: dict[str, float | int | str | bool] = {
            'temperature': self.temperature,
            'seed': seed,
            'max_tokens': self.max_tokens,
            **THINKING_OFF,
        }
        if info.server_version:
            params['ollama_version'] = info.server_version
        return ChatResult(
            content=content,
            info=info,
            params=params,
            prompt_sha256=prompt_hash(messages),
            response_sha256=sha256_hex(content),
            latency_ms=latency_ms,
            tokens_in=_int(usage.get('prompt_tokens')),
            tokens_out=_int(usage.get('completion_tokens')),
            finish_reason=finish if isinstance(finish, str) else None,
        )


def _int(value: object) -> int:
    return value if isinstance(value, int) and value >= 0 else 0
