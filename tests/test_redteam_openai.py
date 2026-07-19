from __future__ import annotations

import builtins
import importlib
import json
import math
import socket
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

import llmfuzz
import llmfuzz.cli as cli
import llmfuzz.redteam_corpus as corpus_module
import llmfuzz.redteam_generation as generation
import llmfuzz.redteam_openai as adapter
from llmfuzz.redteam_corpus import (
    ASSERTION_VOCABULARY,
    ATTACK_CLASSES,
    CASE_SCHEMA_VERSION,
    CORPUS_SCHEMA_VERSION,
)
from llmfuzz.redteam_generation import (
    BudgetState,
    GenerationError,
    GenerationRequest,
    ProviderResponse,
    build_generation_prompt,
    build_output_format,
    generate_and_persist_corpus,
)
from llmfuzz.redteam_openai import (
    OPENAI_API_BASE_URL,
    OPENAI_TIMEOUT_SECONDS,
    OpenAIResponsesProvider,
    create_openai_provider,
)


SECRET_MARKER = "s" + "k-test-" + "secret-must-not-appear"
MALICIOUS_BASE_URL = "https://" + SECRET_MARKER + ".invalid/v1"


@pytest.fixture(autouse=True)
def _block_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def blocked(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("network access is forbidden in C2 tests")

    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    monkeypatch.setattr(socket.socket, "connect", blocked)


def _cases(count: int = 12) -> list[dict[str, object]]:
    return [
        {
            "schema_version": CASE_SCHEMA_VERSION,
            "case_id": f"case_{index:02d}",
            "attack_class": ATTACK_CLASSES[index % len(ATTACK_CLASSES)],
            "input": f"Synthetic input {index}",
            "expected_risk": "critical",
            "rationale": f"Synthetic rationale {index}",
            "assertions": [ASSERTION_VOCABULARY[index % len(ASSERTION_VOCABULARY)]],
        }
        for index in range(count)
    ]


def _sdk_response(
    *,
    output_text: str | None = None,
    status: str = "completed",
    service_tier: object = "default",
    error: object | None = None,
    incomplete_reason: str | None = None,
    usage: object | None = None,
    output: object | None = None,
) -> object:
    if usage is None:
        usage = SimpleNamespace(input_tokens=100, output_tokens=200, total_tokens=300)
    return SimpleNamespace(
        id="resp_adapter_synthetic",
        model="gpt-5.6-sol",
        status=status,
        service_tier=service_tier,
        error=error,
        incomplete_details=(
            None if incomplete_reason is None else SimpleNamespace(reason=incomplete_reason)
        ),
        output_text=(json.dumps({"cases": _cases()}) if output_text is None else output_text),
        usage=usage,
        output=[] if output is None else output,
        _request_id=SECRET_MARKER,
        raw_body=SECRET_MARKER,
    )


class FakeResponses:
    def __init__(self, *items: object) -> None:
        self.items = list(items)
        self.calls: list[dict[str, object]] = []

    def create(self, **kwargs: object) -> object:
        self.calls.append(kwargs)
        item = self.items.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


class FakeClient:
    def __init__(self, *items: object) -> None:
        self.responses = FakeResponses(*items)
        self.close_calls = 0

    def close(self) -> None:
        self.close_calls += 1


class FakeHttpClient:
    def __init__(
        self,
        *,
        trust_env: bool,
        verify: bool = True,
        close_error: BaseException | None = None,
    ) -> None:
        self.trust_env = trust_env
        self.verify = verify
        self.closed = False
        self.close_calls = 0
        self.close_error = close_error

    def close(self) -> None:
        self.close_calls += 1
        self.closed = True
        if self.close_error is not None:
            raise self.close_error


class FactoryInterruption(BaseException):
    pass


class CleanupInterruption(BaseException):
    pass


def _request(max_output_tokens: int = 4096) -> GenerationRequest:
    prompt = build_generation_prompt(12)
    return GenerationRequest(
        model=generation.OPENAI_MODEL,
        instructions=prompt.instructions,
        input=prompt.generation_input,
        max_output_tokens=max_output_tokens,
        text_format=build_output_format(12),
    )


def test_adapter_sends_exact_responses_request_contract() -> None:
    client = FakeClient(_sdk_response())
    provider = OpenAIResponsesProvider(client)

    normalized = provider.create_response(_request())

    assert len(client.responses.calls) == 1
    kwargs = client.responses.calls[0]
    assert set(kwargs) == {
        "model",
        "instructions",
        "input",
        "max_output_tokens",
        "prompt_cache_options",
        "service_tier",
        "store",
        "truncation",
        "text",
        "tools",
    }
    assert kwargs["model"] == "gpt-5.6-sol"
    assert kwargs["max_output_tokens"] == 4096
    assert kwargs["prompt_cache_options"] == {"mode": "explicit"}
    assert kwargs["service_tier"] == "default"
    assert kwargs["store"] is False
    assert kwargs["truncation"] == "disabled"
    assert kwargs["tools"] == []
    assert "prompt_cache_breakpoint" not in json.dumps(kwargs, sort_keys=True)
    assert kwargs["text"] == {"format": build_output_format(12)}
    assert kwargs["text"]["format"]["type"] == "json_schema"  # type: ignore[index]
    assert kwargs["text"]["format"]["strict"] is True  # type: ignore[index]
    assert normalized.response_id == "resp_adapter_synthetic"
    assert normalized.model == "gpt-5.6-sol"
    assert normalized.status == "completed"
    assert normalized.service_tier == "default"
    assert normalized.usage == generation.ProviderUsage(100, 200, 300)


def test_provider_close_forwards_once_and_is_idempotent() -> None:
    client = FakeClient(_sdk_response())
    provider = OpenAIResponsesProvider(client)

    provider.close()
    provider.close()
    provider.close()

    assert client.close_calls == 1


def test_provider_create_after_close_fails_without_sdk_activity() -> None:
    client = FakeClient(_sdk_response())
    provider = OpenAIResponsesProvider(client)
    provider.close()

    with pytest.raises(GenerationError) as exc_info:
        provider.create_response(_request())

    assert exc_info.value.code == "provider_closed"
    assert exc_info.value.__cause__ is None
    assert exc_info.value.__context__ is None
    assert client.responses.calls == []
    assert client.close_calls == 1


def test_provider_close_failure_is_sanitized_and_remains_closed(
    capsys: pytest.CaptureFixture[str],
) -> None:
    class HostileCloseClient(FakeClient):
        def close(self) -> None:
            self.close_calls += 1
            raise RuntimeError(SECRET_MARKER)

    client = HostileCloseClient(_sdk_response())
    provider = OpenAIResponsesProvider(client)

    with pytest.raises(GenerationError) as exc_info:
        provider.close()

    captured = capsys.readouterr()
    assert exc_info.value.code == "provider_close_failed"
    assert exc_info.value.__cause__ is None
    assert exc_info.value.__context__ is None
    assert SECRET_MARKER not in str(exc_info.value)
    assert SECRET_MARKER not in captured.out
    assert SECRET_MARKER not in captured.err
    provider.close()
    with pytest.raises(GenerationError) as closed_info:
        provider.create_response(_request())
    assert closed_info.value.code == "provider_closed"
    assert client.close_calls == 1
    assert client.responses.calls == []


@pytest.mark.parametrize("client", [SimpleNamespace(), SimpleNamespace(close=None)])
def test_provider_missing_or_noncallable_close_fails_deterministically(client: object) -> None:
    provider = OpenAIResponsesProvider(client)

    with pytest.raises(GenerationError) as exc_info:
        provider.close()

    assert exc_info.value.code == "provider_close_failed"
    assert exc_info.value.__cause__ is None
    assert exc_info.value.__context__ is None
    provider.close()


def test_adapter_normalizes_only_safe_error_and_incomplete_categories() -> None:
    client = FakeClient(
        _sdk_response(
            status="incomplete",
            error=SimpleNamespace(message=SECRET_MARKER, body=SECRET_MARKER),
            incomplete_reason=SECRET_MARKER,
        )
    )

    normalized = OpenAIResponsesProvider(client).create_response(_request())

    assert normalized.error_category == "response_error"
    assert normalized.incomplete_reason == "other"
    assert SECRET_MARKER not in repr(normalized)


def test_adapter_detects_refusal_without_exposing_refusal_text() -> None:
    refusal = SimpleNamespace(type="refusal", refusal=SECRET_MARKER)
    message = SimpleNamespace(type="message", content=[refusal])
    client = FakeClient(_sdk_response(output=[message]))

    normalized = OpenAIResponsesProvider(client).create_response(_request())

    assert normalized.refusal is True
    assert SECRET_MARKER not in repr(normalized)


@pytest.mark.parametrize(
    ("class_name", "status", "code", "retryable"),
    [
        ("APIConnectionError", None, "provider_connection", True),
        ("APITimeoutError", None, "provider_timeout", True),
        ("APIStatusError", 408, "provider_http_408", True),
        ("ConflictError", 409, "provider_http_409", True),
        ("RateLimitError", 429, "provider_rate_limit", True),
        ("InternalServerError", 500, "provider_server", True),
        ("APIStatusError", 503, "provider_server", True),
        ("AuthenticationError", 401, "provider_authentication", False),
        ("PermissionDeniedError", 403, "provider_permission", False),
        ("BadRequestError", 400, "provider_bad_request", False),
        ("NotFoundError", 404, "provider_not_found", False),
        ("UnprocessableEntityError", 422, "provider_unprocessable", False),
        ("UnexpectedProviderError", None, "provider_error", False),
    ],
)
def test_sdk_exception_classification_is_sanitized(
    class_name: str,
    status: int | None,
    code: str,
    retryable: bool,
    capsys: pytest.CaptureFixture[str],
) -> None:
    exception_type = type(class_name, (Exception,), {})
    cause = RuntimeError(SECRET_MARKER)
    exception = exception_type(SECRET_MARKER)
    exception.__cause__ = cause
    exception.status_code = status  # type: ignore[attr-defined]
    exception.response = SimpleNamespace(text=SECRET_MARKER, headers={SECRET_MARKER: SECRET_MARKER})  # type: ignore[attr-defined]
    client = FakeClient(exception)

    with pytest.raises(GenerationError) as exc_info:
        OpenAIResponsesProvider(client).create_response(_request())

    captured = capsys.readouterr()
    assert exc_info.value.code == code
    assert exc_info.value.retryable is retryable
    assert exc_info.value.__cause__ is None
    assert exc_info.value.__context__ is None
    assert SECRET_MARKER not in str(exc_info.value)
    assert SECRET_MARKER not in captured.out
    assert SECRET_MARKER not in captured.err


def test_factory_requires_nonblank_environment_key() -> None:
    for environ in ({}, {"OPENAI_API_KEY": ""}, {"OPENAI_API_KEY": "   "}):
        with pytest.raises(GenerationError) as exc_info:
            create_openai_provider(environ=environ)
        assert exc_info.value.code == "missing_api_key"


def test_factory_isolates_http_environment_and_disables_sdk_retries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}
    client = FakeClient(_sdk_response())
    http_clients: list[FakeHttpClient] = []
    for name, value in {
        "HTTP_PROXY": MALICIOUS_BASE_URL,
        "HTTPS_PROXY": MALICIOUS_BASE_URL,
        "ALL_PROXY": MALICIOUS_BASE_URL,
        "NO_PROXY": SECRET_MARKER,
        "SSL_CERT_FILE": SECRET_MARKER,
        "SSL_CERT_DIR": SECRET_MARKER,
    }.items():
        monkeypatch.setenv(name, value)

    def factory(**kwargs: object) -> object:
        captured.update(kwargs)
        return client

    def http_factory(**kwargs: object) -> FakeHttpClient:
        http_client = FakeHttpClient(**kwargs)  # type: ignore[arg-type]
        http_clients.append(http_client)
        return http_client

    provider = create_openai_provider(
        environ={
            "OPENAI_API_KEY": "  synthetic-key  ",
            "UNRELATED_SECRET": SECRET_MARKER,
        },
        client_factory=factory,
        http_client_factory=http_factory,
    )

    assert isinstance(provider, OpenAIResponsesProvider)
    assert len(http_clients) == 1
    assert http_clients[0].trust_env is False
    assert http_clients[0].verify is True
    assert captured["api_key"] == "synthetic-key"
    assert captured["base_url"] == OPENAI_API_BASE_URL
    assert captured["max_retries"] == 0
    assert captured["timeout"] == OPENAI_TIMEOUT_SECONDS
    assert captured["http_client"] is http_clients[0]
    assert math.isfinite(captured["timeout"])  # type: ignore[arg-type]
    assert captured["timeout"] > 0  # type: ignore[operator]
    assert MALICIOUS_BASE_URL not in repr(provider)
    assert SECRET_MARKER not in repr(provider)


def test_provider_close_uses_sdk_client_to_close_injected_http_transport() -> None:
    http_clients: list[FakeHttpClient] = []
    clients: list[FakeClient] = []

    class OwningClient(FakeClient):
        def __init__(self, http_client: FakeHttpClient) -> None:
            super().__init__(_sdk_response())
            self.http_client = http_client

        def close(self) -> None:
            super().close()
            self.http_client.close()

    def http_factory(**kwargs: object) -> FakeHttpClient:
        http_client = FakeHttpClient(**kwargs)  # type: ignore[arg-type]
        http_clients.append(http_client)
        return http_client

    def client_factory(**kwargs: object) -> OwningClient:
        client = OwningClient(kwargs["http_client"])  # type: ignore[arg-type]
        clients.append(client)
        return client

    provider = create_openai_provider(
        environ={"OPENAI_API_KEY": "synthetic-key"},
        client_factory=client_factory,
        http_client_factory=http_factory,
    )
    provider.close()

    assert len(clients) == 1
    assert clients[0].close_calls == 1
    assert len(http_clients) == 1
    assert http_clients[0].closed is True


@pytest.mark.parametrize(
    "name",
    [
        "OPENAI_CUSTOM_HEADERS",
        "OPENAI_ORG_ID",
        "OPENAI_PROJECT_ID",
        "OPENAI_ADMIN_KEY",
        "OPENAI_BASE_URL",
        "OPENAI_LOG",
    ],
)
def test_real_process_openai_environment_is_rejected_before_construction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    name: str,
) -> None:
    client_calls: list[dict[str, object]] = []
    http_calls: list[dict[str, object]] = []
    monkeypatch.setenv(name, SECRET_MARKER)

    def factory(**kwargs: object) -> object:
        client_calls.append(kwargs)
        return FakeClient(_sdk_response())

    def http_factory(**kwargs: object) -> object:
        http_calls.append(kwargs)
        return FakeHttpClient(**kwargs)  # type: ignore[arg-type]

    with pytest.raises(GenerationError) as exc_info:
        create_openai_provider(
            environ={"OPENAI_API_KEY": "synthetic-key"},
            client_factory=factory,
            http_client_factory=http_factory,
        )

    captured = capsys.readouterr()
    assert exc_info.value.code == "openai_environment_not_isolated"
    assert exc_info.value.__cause__ is None
    assert exc_info.value.__context__ is None
    assert SECRET_MARKER not in str(exc_info.value)
    assert SECRET_MARKER not in captured.out
    assert SECRET_MARKER not in captured.err
    assert client_calls == []
    assert http_calls == []
    assert list(tmp_path.iterdir()) == []


def test_selected_openai_environment_is_rejected_before_construction() -> None:
    client_calls: list[dict[str, object]] = []
    http_calls: list[dict[str, object]] = []

    with pytest.raises(GenerationError) as exc_info:
        create_openai_provider(
            environ={
                "OPENAI_API_KEY": "synthetic-key",
                "OPENAI_CUSTOM_HEADERS": SECRET_MARKER,
            },
            client_factory=lambda **kwargs: client_calls.append(kwargs),
            http_client_factory=lambda **kwargs: http_calls.append(kwargs),
        )

    assert exc_info.value.code == "openai_environment_not_isolated"
    assert client_calls == []
    assert http_calls == []


def test_factory_initialization_error_is_sanitized(capsys: pytest.CaptureFixture[str]) -> None:
    http_client = FakeHttpClient(trust_env=False)

    def factory(**_kwargs: object) -> object:
        raise RuntimeError(SECRET_MARKER)

    with pytest.raises(GenerationError) as exc_info:
        create_openai_provider(
            environ={
                "OPENAI_API_KEY": SECRET_MARKER,
            },
            client_factory=factory,
            http_client_factory=lambda **_kwargs: http_client,
        )

    captured = capsys.readouterr()
    assert exc_info.value.code == "provider_initialization"
    assert exc_info.value.__cause__ is None
    assert exc_info.value.__context__ is None
    assert SECRET_MARKER not in str(exc_info.value)
    assert captured.out == ""
    assert captured.err == ""
    assert http_client.closed is True


def test_http_client_factory_exception_is_sanitized_without_client_construction(
    capsys: pytest.CaptureFixture[str],
) -> None:
    marker = SECRET_MARKER
    client_calls: list[dict[str, object]] = []

    def fail_transport(**_kwargs: object) -> object:
        raise RuntimeError(marker)

    with pytest.raises(GenerationError) as exc_info:
        create_openai_provider(
            environ={"OPENAI_API_KEY": marker},
            client_factory=lambda **kwargs: client_calls.append(kwargs),
            http_client_factory=fail_transport,
        )

    captured = capsys.readouterr()
    assert exc_info.value.code == "provider_initialization"
    assert exc_info.value.__cause__ is None
    assert exc_info.value.__context__ is None
    assert client_calls == []
    assert marker not in str(exc_info.value) + captured.out + captured.err


@pytest.mark.parametrize(
    "failure_factory",
    (
        pytest.param(lambda: KeyboardInterrupt(), id="keyboard_interrupt"),
        pytest.param(lambda: SystemExit(73), id="system_exit"),
        pytest.param(lambda: FactoryInterruption(), id="custom_base_exception"),
    ),
)
def test_http_client_factory_base_exception_propagates_without_client_construction(
    capsys: pytest.CaptureFixture[str],
    failure_factory: object,
) -> None:
    client_calls: list[dict[str, object]] = []
    assert callable(failure_factory)
    interruption = failure_factory()

    def fail_transport(**_kwargs: object) -> object:
        raise interruption

    with pytest.raises(type(interruption)) as exc_info:
        create_openai_provider(
            environ={"OPENAI_API_KEY": "synthetic-key"},
            client_factory=lambda **kwargs: client_calls.append(kwargs),
            http_client_factory=fail_transport,
        )

    captured = capsys.readouterr()
    assert exc_info.value is interruption
    assert exc_info.value.__cause__ is None
    assert exc_info.value.__context__ is None
    assert client_calls == []
    assert captured.out == ""
    assert captured.err == ""


@pytest.mark.parametrize(
    "construction_factory",
    (
        pytest.param(lambda marker: RuntimeError(marker), id="runtime_error"),
        pytest.param(lambda _marker: KeyboardInterrupt(), id="keyboard_interrupt"),
        pytest.param(lambda _marker: SystemExit(73), id="system_exit"),
        pytest.param(
            lambda _marker: FactoryInterruption(),
            id="custom_base_exception",
        ),
    ),
)
@pytest.mark.parametrize(
    "cleanup_factory",
    (
        pytest.param(lambda _marker: None, id="close_success"),
        pytest.param(lambda marker: RuntimeError(marker), id="runtime_error"),
        pytest.param(lambda _marker: KeyboardInterrupt(), id="keyboard_interrupt"),
        pytest.param(lambda _marker: SystemExit(74), id="system_exit"),
        pytest.param(
            lambda marker: CleanupInterruption(marker),
            id="custom_base_exception",
        ),
    ),
)
def test_client_factory_failure_always_closes_transport_without_replacing_primary(
    capsys: pytest.CaptureFixture[str],
    construction_factory: object,
    cleanup_factory: object,
) -> None:
    marker = SECRET_MARKER
    assert callable(construction_factory)
    assert callable(cleanup_factory)
    construction_error = construction_factory(marker)
    cleanup_error = cleanup_factory(marker)
    transport = FakeHttpClient(
        trust_env=False,
        close_error=cleanup_error,
    )

    def fail_client(**_kwargs: object) -> object:
        raise construction_error

    if isinstance(construction_error, Exception):
        with pytest.raises(GenerationError) as exc_info:
            create_openai_provider(
                environ={"OPENAI_API_KEY": marker},
                client_factory=fail_client,
                http_client_factory=lambda **_kwargs: transport,
            )
        assert exc_info.value.code == "provider_initialization"
        assert exc_info.value.__cause__ is None
        assert exc_info.value.__context__ is None
        public_error: BaseException = exc_info.value
    else:
        with pytest.raises(type(construction_error)) as exc_info:
            create_openai_provider(
                environ={"OPENAI_API_KEY": marker},
                client_factory=fail_client,
                http_client_factory=lambda **_kwargs: transport,
            )
        assert exc_info.value is construction_error
        assert exc_info.value.__cause__ is None
        assert exc_info.value.__context__ is None
        public_error = exc_info.value

    captured = capsys.readouterr()
    assert transport.close_calls == 1
    assert transport.closed is True
    assert marker not in str(public_error) + captured.out + captured.err


def test_http_client_cleanup_failure_does_not_escape_initialization_error() -> None:
    class HostileHttpClient(FakeHttpClient):
        def close(self) -> None:
            raise RuntimeError(SECRET_MARKER)

    def fail_client(**_kwargs: object) -> object:
        raise RuntimeError(SECRET_MARKER)

    with pytest.raises(GenerationError) as exc_info:
        create_openai_provider(
            environ={"OPENAI_API_KEY": "synthetic-key"},
            client_factory=fail_client,
            http_client_factory=lambda **kwargs: HostileHttpClient(**kwargs),
        )

    assert exc_info.value.code == "provider_initialization"
    assert exc_info.value.__cause__ is None
    assert exc_info.value.__context__ is None
    assert SECRET_MARKER not in str(exc_info.value)


def test_openai_module_import_is_lazy(monkeypatch: pytest.MonkeyPatch) -> None:
    imported_optional: list[str] = []
    real_import = builtins.__import__

    def guarded_import(name: str, *args: object, **kwargs: object) -> object:
        if name in {"openai", "httpx"} or name.startswith(("openai.", "httpx.")):
            imported_optional.append(name)
            raise AssertionError("OpenAI and HTTPX imports must be lazy")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    importlib.reload(adapter)

    assert imported_optional == []


def test_missing_optional_sdk_has_stable_error(monkeypatch: pytest.MonkeyPatch) -> None:
    real_import = builtins.__import__

    def missing_openai(name: str, *args: object, **kwargs: object) -> object:
        if name == "openai":
            raise ImportError("synthetic missing optional dependency")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", missing_openai)
    with pytest.raises(GenerationError) as exc_info:
        adapter.create_openai_provider(environ={"OPENAI_API_KEY": "synthetic"})

    assert exc_info.value.code == "openai_sdk_unavailable"


def test_response_property_failure_has_no_raw_context() -> None:
    class HostileResponse:
        @property
        def error(self) -> object:
            raise RuntimeError(SECRET_MARKER)

    with pytest.raises(GenerationError) as exc_info:
        adapter._normalize_response(HostileResponse())

    assert exc_info.value.code == "provider_response_invalid"
    assert exc_info.value.__cause__ is None
    assert exc_info.value.__context__ is None
    assert SECRET_MARKER not in str(exc_info.value)


def test_hostile_exception_status_property_is_sanitized() -> None:
    class HostileProviderError(Exception):
        @property
        def status_code(self) -> object:
            raise RuntimeError(SECRET_MARKER)

    client = FakeClient(HostileProviderError(SECRET_MARKER))

    with pytest.raises(GenerationError) as exc_info:
        OpenAIResponsesProvider(client).create_response(_request())

    assert exc_info.value.code == "provider_error"
    assert exc_info.value.__cause__ is None
    assert exc_info.value.__context__ is None
    assert SECRET_MARKER not in str(exc_info.value)


def test_import_cli_and_c1_paths_never_construct_client_with_key_present(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    constructions: list[dict[str, object]] = []
    fake_openai = ModuleType("openai")

    class TrapOpenAI:
        def __init__(self, **kwargs: object) -> None:
            constructions.append(kwargs)
            raise AssertionError("real client construction forbidden")

    fake_openai.OpenAI = TrapOpenAI  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "openai", fake_openai)
    monkeypatch.setenv("OPENAI_API_KEY", "synthetic-present-key")

    assert importlib.import_module("llmfuzz") is llmfuzz
    assert importlib.import_module("llmfuzz.redteam_corpus") is corpus_module
    assert importlib.import_module("llmfuzz.redteam_generation") is generation
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["--help"])

    raw_corpus = {
        "schema_version": CORPUS_SCHEMA_VERSION,
        "generation_metadata": {
            "model": "synthetic-model",
            "openai_response_id": "resp_import_test",
            "prompt_sha256": "a" * 64,
            "output_schema_version": CORPUS_SCHEMA_VERSION,
            "generation_timestamp": "2026-07-18T12:34:56Z",
            "requested_case_count": 12,
            "generated_case_count": 12,
            "token_usage": None,
        },
        "cases": _cases(),
    }
    corpus_path = tmp_path / "c1-corpus.json"
    persisted = corpus_module.persist_corpus(raw_corpus, corpus_path)

    assert exc_info.value.code == 0
    assert corpus_module.load_corpus(corpus_path) == persisted
    assert constructions == []


def test_complete_injected_generation_path_never_constructs_real_client(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    constructions: list[dict[str, object]] = []
    fake_openai = ModuleType("openai")

    class TrapOpenAI:
        def __init__(self, **kwargs: object) -> None:
            constructions.append(kwargs)
            raise AssertionError("network client construction forbidden")

    fake_openai.OpenAI = TrapOpenAI  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "openai", fake_openai)
    monkeypatch.setenv("OPENAI_API_KEY", "synthetic-present-key")
    fake_client = FakeClient(_sdk_response())

    result = generate_and_persist_corpus(
        provider=OpenAIResponsesProvider(fake_client),
        path=tmp_path / "corpus.json",
        case_count=12,
        max_output_tokens=1024,
        budget_state=BudgetState(),
    )

    assert result.path.exists()
    assert constructions == []
    assert len(fake_client.responses.calls) == 1


def test_api_key_and_raw_provider_fields_never_enter_result_or_corpus(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    client = FakeClient(_sdk_response())

    def factory(**_kwargs: object) -> object:
        return client

    provider = create_openai_provider(
        environ={
            "OPENAI_API_KEY": SECRET_MARKER,
        },
        client_factory=factory,
        http_client_factory=lambda **kwargs: FakeHttpClient(**kwargs),
    )
    result = generate_and_persist_corpus(
        provider=provider,
        path=tmp_path / "corpus.json",
        case_count=12,
        max_output_tokens=1024,
        budget_state=BudgetState(),
    )

    captured = capsys.readouterr()
    persisted = result.path.read_text(encoding="utf-8")
    assert SECRET_MARKER not in repr(result)
    assert SECRET_MARKER not in persisted
    assert SECRET_MARKER not in captured.out
    assert SECRET_MARKER not in captured.err
    assert MALICIOUS_BASE_URL not in repr(result)
    assert MALICIOUS_BASE_URL not in persisted
    assert MALICIOUS_BASE_URL not in captured.out
    assert MALICIOUS_BASE_URL not in captured.err
    assert "_request_id" not in persisted
    assert "raw_body" not in persisted
