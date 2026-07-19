from __future__ import annotations

import os
from collections.abc import Callable, Mapping

from .redteam_generation import (
    GenerationError,
    GenerationRequest,
    ProviderResponse,
    ProviderUsage,
)


OPENAI_API_BASE_URL = "https://api.openai.com/v1"
OPENAI_TIMEOUT_SECONDS = 60.0
_ALLOWED_OPENAI_ENVIRONMENT = frozenset({"OPENAI_API_KEY"})


def _close_transport_best_effort(transport: object) -> None:
    try:
        close = getattr(transport, "close", None)
        if callable(close):
            close()
    except BaseException:
        pass


def _exception_code(exc: Exception) -> tuple[str, bool]:
    name = exc.__class__.__name__
    try:
        status = getattr(exc, "status_code", None)
    except Exception:
        status = None
    if not isinstance(status, int) or isinstance(status, bool):
        status = None

    if name == "APITimeoutError":
        return "provider_timeout", True
    if name == "APIConnectionError":
        return "provider_connection", True
    if name == "AuthenticationError" or status == 401:
        return "provider_authentication", False
    if name == "PermissionDeniedError" or status == 403:
        return "provider_permission", False
    if name == "NotFoundError" or status == 404:
        return "provider_not_found", False
    if name == "UnprocessableEntityError" or status == 422:
        return "provider_unprocessable", False
    if status == 408:
        return "provider_http_408", True
    if name == "ConflictError" or status == 409:
        return "provider_http_409", True
    if name == "RateLimitError" or status == 429:
        return "provider_rate_limit", True
    if name == "InternalServerError" or (status is not None and status >= 500):
        return "provider_server", True
    if name == "BadRequestError" or status == 400:
        return "provider_bad_request", False
    return "provider_error", False


def _safe_string(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _refusal_present(response: object) -> bool:
    output = getattr(response, "output", None)
    if not isinstance(output, (list, tuple)):
        return False
    for item in output:
        content = getattr(item, "content", None)
        if not isinstance(content, (list, tuple)):
            continue
        for part in content:
            if (
                getattr(part, "type", None) == "refusal"
                or getattr(part, "refusal", None) is not None
            ):
                return True
    return False


def _normalize_response(response: object) -> ProviderResponse:
    failed = False
    try:
        error = getattr(response, "error", None)
        incomplete_details = getattr(response, "incomplete_details", None)
        raw_reason = (
            None if incomplete_details is None else getattr(incomplete_details, "reason", None)
        )
        if raw_reason is None:
            incomplete_reason = None
        elif raw_reason == "max_output_tokens":
            incomplete_reason = "max_output_tokens"
        else:
            incomplete_reason = "other"

        raw_usage = getattr(response, "usage", None)
        usage = None
        if raw_usage is not None:
            usage = ProviderUsage(
                input_tokens=getattr(raw_usage, "input_tokens", None),
                output_tokens=getattr(raw_usage, "output_tokens", None),
                total_tokens=getattr(raw_usage, "total_tokens", None),
            )
        normalized = ProviderResponse(
            response_id=_safe_string(getattr(response, "id", None)),
            model=_safe_string(getattr(response, "model", None)),
            status=_safe_string(getattr(response, "status", None)),
            service_tier=_safe_string(getattr(response, "service_tier", None)),
            error_category=None if error is None else "response_error",
            incomplete_reason=incomplete_reason,
            output_text=_safe_string(getattr(response, "output_text", None)),
            usage=usage,
            refusal=_refusal_present(response),
        )
    except Exception:
        failed = True
    if failed:
        raise GenerationError("provider_response_invalid", retryable=True)
    return normalized


class OpenAIResponsesProvider:
    def __init__(self, client: object) -> None:
        self._client = client
        self._closed = False

    def create_response(self, request: GenerationRequest) -> ProviderResponse:
        if self._closed:
            raise GenerationError("provider_closed")
        provider_error: tuple[str, bool] | None = None
        try:
            responses = getattr(self._client, "responses")
            response = responses.create(
                model=request.model,
                instructions=request.instructions,
                input=request.input,
                max_output_tokens=request.max_output_tokens,
                prompt_cache_options={"mode": "explicit"},
                service_tier="default",
                store=False,
                truncation="disabled",
                text={"format": request.text_format},
                tools=[],
            )
        except GenerationError:
            raise
        except Exception as exc:
            provider_error = _exception_code(exc)
        if provider_error is not None:
            code, retryable = provider_error
            raise GenerationError(code, retryable=retryable)
        return _normalize_response(response)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        close_failed = False
        try:
            close = getattr(self._client, "close", None)
            if callable(close):
                close()
            else:
                close_failed = True
        except Exception:
            close_failed = True
        if close_failed:
            raise GenerationError("provider_close_failed")


def create_openai_provider(
    *,
    environ: Mapping[str, str] | None = None,
    client_factory: Callable[..., object] | None = None,
    http_client_factory: Callable[..., object] | None = None,
) -> OpenAIResponsesProvider:
    environment = os.environ if environ is None else environ
    environment_invalid = False
    raw_key: object = None
    try:
        for source in (environment, os.environ):
            for name in source:
                if (
                    isinstance(name, str)
                    and name.startswith("OPENAI_")
                    and name not in _ALLOWED_OPENAI_ENVIRONMENT
                ):
                    environment_invalid = True
                    break
            if environment_invalid:
                break
        if not environment_invalid:
            raw_key = environment.get("OPENAI_API_KEY")
    except Exception:
        environment_invalid = True
    if environment_invalid:
        raise GenerationError("openai_environment_not_isolated")
    if not isinstance(raw_key, str) or not raw_key.strip():
        raise GenerationError("missing_api_key")
    api_key = raw_key.strip()

    if client_factory is None or http_client_factory is None:
        sdk_missing = False
        try:
            from openai import DefaultHttpxClient, OpenAI
        except ImportError:
            sdk_missing = True
        if sdk_missing:
            raise GenerationError("openai_sdk_unavailable")
        if client_factory is None:
            client_factory = OpenAI
        if http_client_factory is None:
            http_client_factory = DefaultHttpxClient
    transport_failed = False
    try:
        http_client = http_client_factory(trust_env=False)
    except Exception:
        transport_failed = True
    if transport_failed:
        raise GenerationError("provider_initialization")

    initialization_failed = False
    try:
        client = client_factory(
            api_key=api_key,
            base_url=OPENAI_API_BASE_URL,
            max_retries=0,
            timeout=OPENAI_TIMEOUT_SECONDS,
            http_client=http_client,
        )
    except Exception:
        initialization_failed = True
    except BaseException:
        _close_transport_best_effort(http_client)
        raise
    if initialization_failed:
        _close_transport_best_effort(http_client)
        raise GenerationError("provider_initialization")
    return OpenAIResponsesProvider(client)
