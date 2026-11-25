"""G1: LLM variant generator (phase-5.md §5.3.3).

Usage::

    from redteam.gen_llm import ChatClient, generate_g1, G1_FALLBACK_MODELS

    with ChatClient() as client:  # local Ollama, qwen3.8:27b-mlx
        result = generate_g1(
            seeds, run_seed=1234, round=1, client=client,
            validator=validator, audit=AuditLog(store.audit_path),
            fallback_models=G1_FALLBACK_MODELS,
        )
    store.add_variants(result.variants)

Payloads are never executed and never logged; see ``generate`` for the
audit rules.
"""

from .client import (
    DEFAULT_BASE_URL,
    DEFAULT_MODEL,
    G1_MAX_OUTPUT_TOKENS,
    G1_MAX_RESPONSE_BYTES,
    G1_TEMPERATURE,
    G1_TIMEOUT_S,
    G1_VARIANTS_PER_CALL,
    ChatClient,
    ChatResult,
    G1ClientError,
    ServerInfo,
    output_schema,
    request_seed,
)
from .generate import (
    G1_FALLBACK_MODELS,
    G1_MAX_ATTEMPTS,
    G1_PILOT_CALLS,
    G1_REFUSAL_THRESHOLD,
    G1Output,
    G1Stats,
    GenerationResult,
    ModelSwitch,
    current_scorer,
    g1_variant_id,
    generate_g1,
    parse_output,
    technique_slug,
)
from .prompts import SYSTEM_PROMPT, Feedback, build_messages, wrap_payload

__all__ = [
    'DEFAULT_BASE_URL',
    'DEFAULT_MODEL',
    'G1_FALLBACK_MODELS',
    'G1_MAX_ATTEMPTS',
    'G1_MAX_OUTPUT_TOKENS',
    'G1_MAX_RESPONSE_BYTES',
    'G1_PILOT_CALLS',
    'G1_REFUSAL_THRESHOLD',
    'G1_TEMPERATURE',
    'G1_TIMEOUT_S',
    'G1_VARIANTS_PER_CALL',
    'SYSTEM_PROMPT',
    'ChatClient',
    'ChatResult',
    'Feedback',
    'G1ClientError',
    'G1Output',
    'G1Stats',
    'GenerationResult',
    'ModelSwitch',
    'ServerInfo',
    'build_messages',
    'current_scorer',
    'g1_variant_id',
    'generate_g1',
    'output_schema',
    'parse_output',
    'request_seed',
    'technique_slug',
    'wrap_payload',
]
