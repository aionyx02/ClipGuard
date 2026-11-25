import json

import httpx
import pytest
from g1_fakes import DIGEST, VERSION, FakeOllama, J, variants_json

from redteam.gen_llm import (
    G1_TEMPERATURE,
    G1_VARIANTS_PER_CALL,
    G1ClientError,
    build_messages,
    output_schema,
    request_seed,
)
from redteam.models import Shell


def _ok(body, n):
    return variants_json(('sh', 'echo hi', 'quote'))


def test_schema_shape():
    schema = output_schema()
    arr = schema['properties']['variants']
    assert arr['maxItems'] == G1_VARIANTS_PER_CALL
    item = arr['items']
    assert item['additionalProperties'] is False
    assert set(item['required']) == {'shell', 'payload', 'technique'}
    assert set(item['properties']['shell']['enum']) == {s.value for s in Shell}
    # Lengths are validated locally, not cut by the server grammar.
    assert 'maxLength' not in json.dumps(schema)


def test_request_body_has_no_tools_and_thinking_off():
    fake = FakeOllama(_ok)
    client = fake.client()
    result = client.complete(build_messages('echo hi', Shell.SH), seed=42)
    (body,) = fake.requests
    assert 'tools' not in body and 'tool_choice' not in body
    assert 'functions' not in body
    assert body['reasoning_effort'] == 'none'
    assert body['response_format']['type'] == 'json_schema'
    assert body['response_format']['json_schema']['schema'] == output_schema()
    assert body['seed'] == 42
    assert body['temperature'] == G1_TEMPERATURE
    assert body['stream'] is False
    assert result.params['seed'] == 42
    assert result.params['temperature'] == G1_TEMPERATURE
    assert result.params['ollama_version'] == VERSION
    assert result.info.model_ref == f'primary:1b@{DIGEST[:12]}'
    assert result.tokens_in == 11 and result.tokens_out == 7


def test_content_not_in_repr():
    marker = J('MARK', 'ER_RESPONSE_1')
    fake = FakeOllama(lambda b, n: marker)
    result = fake.client().complete(build_messages('x', Shell.SH), seed=1)
    assert result.content == marker
    assert marker not in repr(result)


def test_unknown_model_has_no_digest():
    fake = FakeOllama(_ok, models=('other:1b',))
    info = fake.client('primary:1b').info()
    assert info.digest is None and info.model_ref == 'primary:1b'


def test_request_seed_stable_and_distinct():
    a = request_seed(7, 'case.a', 1)
    assert a == request_seed(7, 'case.a', 1)
    assert 0 <= a < 2**31
    others = {
        request_seed(7, 'case.a', 2),
        request_seed(7, 'case.b', 1),
        request_seed(8, 'case.a', 1),
    }
    assert a not in others and len(others) == 3


def test_response_size_cap():
    big = 'x' * 5000
    fake = FakeOllama(lambda b, n: big)
    client = fake.client(max_response_bytes=1024)
    with pytest.raises(G1ClientError) as e:
        client.complete(build_messages('x', Shell.SH), seed=1)
    assert e.value.kind == 'response-too-large'


@pytest.mark.parametrize(
    ('response', 'kind'),
    [
        (httpx.Response(500, text='boom secret'), 'http-500'),
        (httpx.Response(200, text='not json'), 'bad-envelope'),
        (httpx.Response(200, json={'choices': []}), 'bad-envelope'),
    ],
)
def test_errors_carry_kind_only(response, kind):
    fake = FakeOllama(lambda b, n: response)
    marker = J('MARK', 'ER_PROMPT_2')
    with pytest.raises(G1ClientError) as e:
        fake.client().complete(build_messages(marker, Shell.SH), seed=1)
    assert str(e.value) == kind
    assert marker not in repr(e.value)


def test_timeout_is_an_error_kind():
    def handler(request):
        if request.url.path.startswith('/api/'):
            return httpx.Response(404)
        raise httpx.ReadTimeout('slow', request=request)

    from redteam.gen_llm import ChatClient

    client = ChatClient('m', transport=httpx.MockTransport(handler))
    with pytest.raises(G1ClientError) as e:
        client.complete(build_messages('x', Shell.SH), seed=1)
    assert e.value.kind == 'timeout'


def test_with_model_keeps_settings():
    fake = FakeOllama(_ok)
    client = fake.client(temperature=0.3)
    other = client.with_model('backup:1b')
    other.complete(build_messages('x', Shell.SH), seed=1)
    assert fake.requests[0]['model'] == 'backup:1b'
    assert fake.requests[0]['temperature'] == 0.3
