from __future__ import annotations

import hashlib
import json
import os
import socket
from collections.abc import Callable
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from decimal import Context, Decimal, ROUND_CEILING, ROUND_DOWN, getcontext, localcontext
from pathlib import Path

import pytest

import llmfuzz.redteam_generation as generation
from llmfuzz.redteam_corpus import (
    ASSERTION_VOCABULARY,
    ATTACK_CLASSES,
    CASE_SCHEMA_VERSION,
    CORPUS_SCHEMA_VERSION,
    MAX_CASE_COUNT,
    MAX_CASE_ID_CHARS,
    MAX_INPUT_CHARS,
    MAX_RATIONALE_CHARS,
    MIN_CASE_COUNT,
    CorpusValidationError,
    load_corpus,
)
from llmfuzz.redteam_generation import (
    CACHE_WRITE_USD_PER_MILLION_TOKENS,
    HARD_PROJECT_COST_CEILING_USD,
    INPUT_RESERVATION_USD_PER_MILLION_TOKENS,
    INPUT_USD_PER_MILLION_TOKENS,
    LONG_CONTEXT_INPUT_TOKEN_THRESHOLD,
    MAX_OUTPUT_TOKENS,
    MAX_PROJECT_ATTEMPTS,
    OPENAI_MODEL,
    OUTPUT_SCHEMA_NAME,
    OUTPUT_USD_PER_MILLION_TOKENS,
    BudgetState,
    GenerationError,
    ProviderResponse,
    ProviderUsage,
    build_generation_prompt,
    build_output_format,
    calculate_actual_cost,
    calculate_worst_case_reservation,
    generate_and_persist_corpus,
    validate_budget_state,
)


FIXED_TIME = datetime(2026, 7, 18, 12, 34, 56, tzinfo=timezone.utc)
SECRET_MARKER = "s" + "k-test-" + "secret-must-not-appear"


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
            "input": f"Synthetic adversarial input {index}",
            "expected_risk": "critical",
            "rationale": f"Concise synthetic rationale {index}",
            "assertions": [ASSERTION_VOCABULARY[index % len(ASSERTION_VOCABULARY)]],
        }
        for index in range(count)
    ]


def _response(
    count: int = 12,
    *,
    response_id: str = "resp_synthetic_c2",
    model: str = "gpt-5.6-sol",
    status: str = "completed",
    service_tier: object = "default",
    output_text: str | None = None,
    usage: ProviderUsage | None = ProviderUsage(100, 200, 300),
    error_category: str | None = None,
    incomplete_reason: str | None = None,
    refusal: bool = False,
) -> ProviderResponse:
    return ProviderResponse(
        response_id=response_id,
        model=model,
        status=status,
        service_tier=service_tier,  # type: ignore[arg-type]
        error_category=error_category,
        incomplete_reason=incomplete_reason,
        output_text=(json.dumps({"cases": _cases(count)}) if output_text is None else output_text),
        usage=usage,
        refusal=refusal,
    )


class QueueProvider:
    def __init__(self, *items: object) -> None:
        self.items = list(items)
        self.calls: list[generation.GenerationRequest] = []

    def create_response(self, request: generation.GenerationRequest) -> ProviderResponse:
        self.calls.append(request)
        item = self.items.pop(0)
        if isinstance(item, Exception):
            raise item
        assert isinstance(item, ProviderResponse)
        return item


def _generate(
    tmp_path: Path,
    provider: QueueProvider,
    *,
    count: int = 12,
    max_output_tokens: int = 1024,
    state: BudgetState | None = None,
    name: str = "corpus.json",
    path: object | None = None,
    clock: Callable[[], object] | None = None,
) -> generation.GenerationResult:
    return generate_and_persist_corpus(
        provider=provider,
        path=tmp_path / name if path is None else path,  # type: ignore[arg-type]
        case_count=count,
        max_output_tokens=max_output_tokens,
        budget_state=state or BudgetState(),
        clock=(lambda: FIXED_TIME) if clock is None else clock,  # type: ignore[arg-type]
    )


def _reservation(count: int = 12, output_tokens: int = 1024) -> Decimal:
    return _reservation_details(count, output_tokens)[1]


def _reservation_details(
    count: int = 12,
    output_tokens: int = 1024,
) -> tuple[int, Decimal]:
    prompt = build_generation_prompt(count)
    return calculate_worst_case_reservation(
        prompt=prompt,
        text_format=build_output_format(count),
        max_output_tokens=output_tokens,
    )


def _supported_reservation_bounds_oracle() -> tuple[Decimal, Decimal]:
    reservations = [
        _reservation(count, output_tokens)
        for count in range(MIN_CASE_COUNT, MAX_CASE_COUNT + 1)
        for output_tokens in (1, MAX_OUTPUT_TOKENS)
    ]
    return min(reservations), max(reservations)


def _exact_money_product(value: Decimal, multiplier: int) -> Decimal:
    with localcontext(Context(prec=50, rounding=ROUND_CEILING)):
        return value * Decimal(multiplier)


def test_prompt_contract_bytes_and_hash_are_deterministic() -> None:
    first = build_generation_prompt(12)
    second = build_generation_prompt(12)
    decoded = json.loads(first.contract_bytes)

    assert first == second
    assert first.contract_bytes.endswith(b"\n")
    assert first.contract_bytes.count(b"\n") == 1
    assert first.sha256 == hashlib.sha256(first.contract_bytes).hexdigest()
    assert decoded == {
        "generation_input": first.generation_input,
        "instructions": first.instructions,
        "output_schema_name": OUTPUT_SCHEMA_NAME,
        "output_schema_version": CORPUS_SCHEMA_VERSION,
        "prompt_contract_version": generation.PROMPT_CONTRACT_VERSION,
        "requested_case_count": 12,
    }
    assert "exactly 12 cases" in first.instructions
    assert "chain-of-thought" in first.instructions
    assert "real credentials" in first.instructions


def test_prompt_hash_changes_with_case_count() -> None:
    assert build_generation_prompt(12).sha256 != build_generation_prompt(20).sha256


def test_prompt_hash_changes_with_instruction_or_schema_contract() -> None:
    prompt = build_generation_prompt(12)
    changed_instruction = generation._prompt_contract_bytes(
        instructions=prompt.instructions + " Changed.",
        generation_input=prompt.generation_input,
        requested_case_count=12,
        output_schema_name=OUTPUT_SCHEMA_NAME,
        output_schema_version=CORPUS_SCHEMA_VERSION,
    )
    changed_schema = generation._prompt_contract_bytes(
        instructions=prompt.instructions,
        generation_input=prompt.generation_input,
        requested_case_count=12,
        output_schema_name="changed_schema",
        output_schema_version=CORPUS_SCHEMA_VERSION,
    )

    assert hashlib.sha256(changed_instruction).hexdigest() != prompt.sha256
    assert hashlib.sha256(changed_schema).hexdigest() != prompt.sha256


def _all_object_schemas(value: object) -> list[dict[str, object]]:
    found: list[dict[str, object]] = []
    if isinstance(value, dict):
        if value.get("type") == "object":
            found.append(value)
        for child in value.values():
            found.extend(_all_object_schemas(child))
    elif isinstance(value, list):
        for child in value:
            found.extend(_all_object_schemas(child))
    return found


def _schema_keywords(value: object) -> set[str]:
    keywords: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            keywords.add(key)
            if key == "properties":
                assert isinstance(child, dict)
                for property_schema in child.values():
                    keywords.update(_schema_keywords(property_schema))
            else:
                keywords.update(_schema_keywords(child))
    elif isinstance(value, list):
        for child in value:
            keywords.update(_schema_keywords(child))
    return keywords


@pytest.mark.parametrize("count", [12, 20])
def test_strict_output_schema_reuses_c1_contract(count: int) -> None:
    output_format = build_output_format(count)
    schema = output_format["schema"]
    cases_schema = schema["properties"]["cases"]  # type: ignore[index]
    case_schema = cases_schema["items"]
    properties = case_schema["properties"]

    assert output_format["type"] == "json_schema"
    assert output_format["name"] == OUTPUT_SCHEMA_NAME
    assert output_format["strict"] is True
    assert cases_schema["minItems"] == count
    assert cases_schema["maxItems"] == count
    assert properties["schema_version"]["enum"] == [CASE_SCHEMA_VERSION]
    assert properties["case_id"]["pattern"] == r"^[a-z0-9._-]{1,64}$"
    assert properties["attack_class"]["enum"] == list(ATTACK_CLASSES)
    assert properties["input"]["pattern"] == r".*\S.*"
    assert properties["expected_risk"]["enum"] == ["critical"]
    assert properties["rationale"]["pattern"] == r".*\S.*"
    assert properties["assertions"]["items"]["enum"] == list(ASSERTION_VOCABULARY)
    assert all(item["additionalProperties"] is False for item in _all_object_schemas(schema))


def test_output_schema_uses_only_authorized_structured_output_keywords() -> None:
    keywords = _schema_keywords(build_output_format(12))
    allowed = {
        "type",
        "name",
        "strict",
        "schema",
        "properties",
        "required",
        "additionalProperties",
        "items",
        "enum",
        "pattern",
        "minItems",
        "maxItems",
    }

    assert keywords <= allowed
    assert not {"const", "uniqueItems", "minLength", "maxLength"} & keywords


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("case_id", "a" * (MAX_CASE_ID_CHARS + 1)),
        ("input", "x" * (MAX_INPUT_CHARS + 1)),
        ("rationale", "x" * (MAX_RATIONALE_CHARS + 1)),
    ],
)
def test_local_c1_validation_enforces_limits_removed_from_wire_schema(
    tmp_path: Path,
    field: str,
    value: str,
) -> None:
    cases = _cases()
    cases[0][field] = value
    invalid = _response(output_text=json.dumps({"cases": cases}))
    provider = QueueProvider(invalid, invalid)

    with pytest.raises(GenerationError) as exc_info:
        _generate(tmp_path, provider)

    assert exc_info.value.code == "response_invalid_payload"
    assert len(provider.calls) == 2
    assert not (tmp_path / "corpus.json").exists()


@pytest.mark.parametrize("value", [11, 21, True])
def test_case_count_guard_rejects_invalid_values(value: object) -> None:
    with pytest.raises(GenerationError, match="configuration"):
        build_generation_prompt(value)  # type: ignore[arg-type]


@pytest.mark.parametrize("value", [1, MAX_OUTPUT_TOKENS])
def test_output_token_bounds_accept_endpoints(value: int) -> None:
    prompt = build_generation_prompt(12)
    input_bound, reservation = calculate_worst_case_reservation(
        prompt=prompt,
        text_format=build_output_format(12),
        max_output_tokens=value,
    )

    assert input_bound == len(prompt.contract_bytes) + len(
        generation._canonical_json_bytes(build_output_format(12))
    )
    expected = Decimal(input_bound) * Decimal("6.25") / Decimal(1_000_000)
    expected += Decimal(value) * OUTPUT_USD_PER_MILLION_TOKENS / Decimal(1_000_000)
    assert CACHE_WRITE_USD_PER_MILLION_TOKENS == Decimal("6.25")
    assert INPUT_RESERVATION_USD_PER_MILLION_TOKENS == max(
        INPUT_USD_PER_MILLION_TOKENS,
        CACHE_WRITE_USD_PER_MILLION_TOKENS,
    )
    assert reservation == expected


def test_input_bound_covers_complete_application_token_contract() -> None:
    prompt = build_generation_prompt(12)
    text_format = build_output_format(12)
    input_bound, _ = calculate_worst_case_reservation(
        prompt=prompt,
        text_format=text_format,
        max_output_tokens=1024,
    )
    token_bearing_request = generation._canonical_json_bytes(
        {
            "instructions": prompt.instructions,
            "input": prompt.generation_input,
            "text": {"format": text_format},
        }
    )

    assert input_bound >= len(token_bearing_request)
    assert prompt.instructions.encode("utf-8") in token_bearing_request
    assert prompt.generation_input.encode("utf-8") in token_bearing_request
    assert generation._canonical_json_bytes(text_format).rstrip(b"\n") in token_bearing_request


@pytest.mark.parametrize("value", [0, MAX_OUTPUT_TOKENS + 1, True])
def test_output_token_bounds_reject_invalid_values(value: object) -> None:
    with pytest.raises(GenerationError, match="configuration"):
        calculate_worst_case_reservation(
            prompt=build_generation_prompt(12),
            text_format=build_output_format(12),
            max_output_tokens=value,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    "state",
    [
        BudgetState(attempts_consumed=-1),
        BudgetState(max_project_attempts=MAX_PROJECT_ATTEMPTS + 1),
        BudgetState(project_cost_cap_usd=HARD_PROJECT_COST_CEILING_USD + Decimal("0.01")),
        BudgetState(project_cost_cap_usd=Decimal("NaN")),
        BudgetState(project_cost_cap_usd=Decimal("Infinity")),
        BudgetState(project_cost_cap_usd=Decimal("-1")),
        BudgetState(reserved_cost_usd=Decimal("NaN")),
        BudgetState(project_cost_cap_usd=Decimal("1"), reserved_cost_usd=Decimal("2")),
        BudgetState(
            attempts_consumed=1,
            reserved_cost_usd=_reservation(),
            usage_reports_observed=True,  # type: ignore[arg-type]
        ),
        BudgetState(usage_reports_observed=1),
        BudgetState(
            attempts_consumed=1,
            reserved_cost_usd=_reservation(),
            usage_reports_observed=1,
            known_input_tokens=True,  # type: ignore[arg-type]
        ),
        BudgetState(
            attempts_consumed=1,
            reserved_cost_usd=_reservation(),
            usage_reports_observed=1,
            known_input_tokens=1,
            known_total_tokens=2,
        ),
        BudgetState(
            attempts_consumed=1,
            reserved_cost_usd=_reservation(),
            usage_reports_observed=1,
            known_actual_cost_usd=Decimal("1"),
        ),
    ],
)
def test_invalid_budget_state_is_rejected(state: BudgetState) -> None:
    with pytest.raises(GenerationError, match="configuration"):
        validate_budget_state(state)


def test_zero_attempt_reservation_history_is_consistent_only_at_zero() -> None:
    validate_budget_state(BudgetState())

    with pytest.raises(GenerationError) as exc_info:
        validate_budget_state(BudgetState(reserved_cost_usd=Decimal("0.00000001")))

    assert exc_info.value.code == "invalid_configuration"


@pytest.mark.parametrize("attempts", [1, 2, MAX_PROJECT_ATTEMPTS])
def test_reservation_history_accepts_only_supported_cumulative_envelope(
    attempts: int,
) -> None:
    minimum, maximum = _supported_reservation_bounds_oracle()
    cumulative_minimum = _exact_money_product(minimum, attempts)
    cumulative_maximum = _exact_money_product(maximum, attempts)

    validate_budget_state(
        BudgetState(attempts_consumed=attempts, reserved_cost_usd=cumulative_minimum)
    )
    validate_budget_state(
        BudgetState(attempts_consumed=attempts, reserved_cost_usd=cumulative_maximum)
    )

    with pytest.raises(GenerationError):
        validate_budget_state(
            BudgetState(
                attempts_consumed=attempts,
                reserved_cost_usd=cumulative_minimum - Decimal("0.00000001"),
            )
        )
    with pytest.raises(GenerationError):
        validate_budget_state(
            BudgetState(
                attempts_consumed=attempts,
                reserved_cost_usd=cumulative_maximum + Decimal("0.00000001"),
            )
        )


def test_one_attempt_with_zero_reservation_is_rejected() -> None:
    with pytest.raises(GenerationError) as exc_info:
        validate_budget_state(BudgetState(attempts_consumed=1))

    assert exc_info.value.code == "invalid_configuration"


def test_supported_reservation_bounds_are_context_independent() -> None:
    expected_minimum, expected_maximum = _supported_reservation_bounds_oracle()
    cumulative_minimum = _exact_money_product(expected_minimum, MAX_PROJECT_ATTEMPTS)
    cumulative_maximum = _exact_money_product(expected_maximum, MAX_PROJECT_ATTEMPTS)
    original = getcontext()
    original_settings = (original.prec, original.rounding, original.Emin, original.Emax)

    with localcontext() as hostile:
        hostile.prec = 1
        hostile.rounding = ROUND_DOWN
        actual_minimum, actual_maximum = generation._supported_attempt_reservation_bounds()
        validate_budget_state(
            BudgetState(
                attempts_consumed=MAX_PROJECT_ATTEMPTS,
                reserved_cost_usd=cumulative_minimum,
            )
        )
        validate_budget_state(
            BudgetState(
                attempts_consumed=MAX_PROJECT_ATTEMPTS,
                reserved_cost_usd=cumulative_maximum,
            )
        )
        with pytest.raises(GenerationError):
            validate_budget_state(
                BudgetState(
                    attempts_consumed=MAX_PROJECT_ATTEMPTS,
                    reserved_cost_usd=cumulative_minimum - Decimal("0.00000001"),
                )
            )

    assert (actual_minimum, actual_maximum) == (expected_minimum, expected_maximum)
    assert getcontext() is original
    assert (
        getcontext().prec,
        getcontext().rounding,
        getcontext().Emin,
        getcontext().Emax,
    ) == original_settings


def test_float_currency_state_is_rejected() -> None:
    state = BudgetState(project_cost_cap_usd=1.0)  # type: ignore[arg-type]

    with pytest.raises(GenerationError, match="configuration"):
        validate_budget_state(state)


def test_long_context_threshold_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        generation,
        "_input_token_upper_bound",
        lambda _prompt, _format: LONG_CONTEXT_INPUT_TOKEN_THRESHOLD,
    )

    with pytest.raises(GenerationError, match="configuration"):
        calculate_worst_case_reservation(
            prompt=build_generation_prompt(12),
            text_format=build_output_format(12),
            max_output_tokens=1024,
        )


def test_money_arithmetic_is_independent_of_ambient_decimal_context() -> None:
    prompt = build_generation_prompt(12)
    text_format = build_output_format(12)
    input_bound = len(prompt.contract_bytes) + len(
        generation._canonical_json_bytes(text_format)
    )
    with localcontext(Context(prec=50, rounding=ROUND_CEILING)):
        expected_reservation = (
            Decimal(input_bound) * Decimal("6.25") / Decimal("1000000")
            + Decimal(MAX_OUTPUT_TOKENS) * Decimal("30.00") / Decimal("1000000")
        )
        expected_actual = (
            Decimal(123) * Decimal("5.00") / Decimal("1000000")
            + Decimal(456) * Decimal("30.00") / Decimal("1000000")
        )
    original = getcontext()
    original_settings = (original.prec, original.rounding, original.Emin, original.Emax)

    with localcontext() as hostile:
        hostile.prec = 1
        hostile.rounding = ROUND_DOWN
        _, reservation = calculate_worst_case_reservation(
            prompt=prompt,
            text_format=text_format,
            max_output_tokens=MAX_OUTPUT_TOKENS,
        )
        actual = calculate_actual_cost(generation.TokenUsage(123, 456, 579))

    assert reservation == expected_reservation
    assert actual == expected_actual
    assert getcontext() is original
    assert (
        getcontext().prec,
        getcontext().rounding,
        getcontext().Emin,
        getcontext().Emax,
    ) == original_settings


def test_hostile_decimal_context_cannot_admit_second_maximum_attempt() -> None:
    reservation = _reservation(output_tokens=MAX_OUTPUT_TOKENS)
    state = BudgetState(project_cost_cap_usd=Decimal("1"))
    original = getcontext()
    original_settings = (original.prec, original.rounding, original.Emin, original.Emax)

    with localcontext() as hostile:
        hostile.prec = 1
        hostile.rounding = ROUND_DOWN
        generation._reserve_attempt(state, reservation)
        with pytest.raises(GenerationError) as exc_info:
            generation._reserve_attempt(state, reservation)

    assert exc_info.value.code == "budget_limit_exceeded"
    assert state.attempts_consumed == 1
    assert state.reserved_cost_usd == reservation
    assert state.attempts_consumed < MAX_PROJECT_ATTEMPTS
    assert getcontext() is original
    assert (
        getcontext().prec,
        getcontext().rounding,
        getcontext().Emin,
        getcontext().Emax,
    ) == original_settings


def test_each_internal_attempt_mutation_preserves_valid_history() -> None:
    reservation = _reservation()
    state = BudgetState()

    for attempts in range(1, MAX_PROJECT_ATTEMPTS + 1):
        generation._reserve_attempt(state, reservation)
        validate_budget_state(state)
        assert state.attempts_consumed == attempts
        assert state.reserved_cost_usd == _exact_money_product(reservation, attempts)

    assert state.project_cost_cap_usd == HARD_PROJECT_COST_CEILING_USD


def test_cumulative_known_cost_is_stable_under_hostile_decimal_context() -> None:
    state = BudgetState(attempts_consumed=2, reserved_cost_usd=_reservation() * 2)
    first = generation.TokenUsage(123, 456, 579)
    second = generation.TokenUsage(321, 654, 975)
    with localcontext(Context(prec=50, rounding=ROUND_CEILING)):
        expected = (
            Decimal(444) * Decimal("5.00") / Decimal("1000000")
            + Decimal(1110) * Decimal("30.00") / Decimal("1000000")
        )
    original = getcontext()

    with localcontext() as hostile:
        hostile.prec = 1
        hostile.rounding = ROUND_DOWN
        generation._record_usage(state, first, calculate_actual_cost(first))
        generation._record_usage(state, second, calculate_actual_cost(second))

    assert state.usage_reports_observed == 2
    assert state.known_input_tokens == 444
    assert state.known_output_tokens == 1110
    assert state.known_total_tokens == 1554
    assert state.known_actual_cost_usd == expected
    assert getcontext() is original


def test_first_call_consumes_attempt_and_reservation(tmp_path: Path) -> None:
    state = BudgetState()
    result = _generate(tmp_path, QueueProvider(_response()), state=state)

    assert state.attempts_consumed == 1
    assert state.reserved_cost_usd == _reservation()
    assert result.budget_state is state
    assert result.evidence.attempts_consumed == 1
    assert result.evidence.reserved_maximum_cost_usd == _reservation()


@pytest.mark.parametrize(
    "code",
    [
        "provider_connection",
        "provider_timeout",
        "provider_http_408",
        "provider_http_409",
        "provider_rate_limit",
        "provider_server",
    ],
)
def test_retryable_provider_failure_then_success(tmp_path: Path, code: str) -> None:
    provider = QueueProvider(GenerationError(code, retryable=True), _response())
    state = BudgetState()

    result = _generate(tmp_path, provider, state=state)

    assert len(provider.calls) == 2
    assert state.attempts_consumed == 2
    assert state.reserved_cost_usd == _reservation() * 2
    assert result.evidence.attempts_consumed == 2


def test_starting_at_project_attempt_cap_makes_zero_calls(tmp_path: Path) -> None:
    provider = QueueProvider(_response())
    state = BudgetState(
        attempts_consumed=MAX_PROJECT_ATTEMPTS,
        reserved_cost_usd=_reservation() * MAX_PROJECT_ATTEMPTS,
    )

    with pytest.raises(GenerationError) as exc_info:
        _generate(tmp_path, provider, state=state)

    assert exc_info.value.code == "attempt_limit_exceeded"
    assert provider.calls == []


def test_starting_with_one_attempt_remaining_blocks_retry(tmp_path: Path) -> None:
    provider = QueueProvider(
        GenerationError("provider_connection", retryable=True),
        _response(),
    )
    state = BudgetState(
        attempts_consumed=MAX_PROJECT_ATTEMPTS - 1,
        reserved_cost_usd=_reservation() * (MAX_PROJECT_ATTEMPTS - 1),
    )

    with pytest.raises(GenerationError) as exc_info:
        _generate(tmp_path, provider, state=state)

    assert exc_info.value.code == "attempt_limit_exceeded"
    assert len(provider.calls) == 1
    assert state.attempts_consumed == MAX_PROJECT_ATTEMPTS


def test_two_failures_make_exactly_two_calls_and_never_refund(tmp_path: Path) -> None:
    provider = QueueProvider(
        GenerationError("provider_connection", retryable=True),
        GenerationError("provider_timeout", retryable=True),
        _response(),
    )
    state = BudgetState()

    with pytest.raises(GenerationError) as exc_info:
        _generate(tmp_path, provider, state=state)

    assert exc_info.value.code == "provider_timeout"
    assert len(provider.calls) == 2
    assert state.attempts_consumed == 2
    assert state.reserved_cost_usd == _reservation() * 2
    assert not (tmp_path / "corpus.json").exists()


def test_insufficient_budget_makes_zero_calls(tmp_path: Path) -> None:
    reservation = _reservation()
    provider = QueueProvider(_response())
    state = BudgetState(project_cost_cap_usd=reservation - Decimal("0.000001"))

    with pytest.raises(GenerationError) as exc_info:
        _generate(tmp_path, provider, state=state)

    assert exc_info.value.code == "budget_limit_exceeded"
    assert provider.calls == []
    assert state.reserved_cost_usd == 0


def test_budget_for_one_attempt_blocks_retry(tmp_path: Path) -> None:
    reservation = _reservation()
    provider = QueueProvider(
        GenerationError("provider_connection", retryable=True),
        _response(),
    )
    state = BudgetState(project_cost_cap_usd=reservation)

    with pytest.raises(GenerationError) as exc_info:
        _generate(tmp_path, provider, state=state)

    assert exc_info.value.code == "budget_limit_exceeded"
    assert len(provider.calls) == 1
    assert state.reserved_cost_usd == reservation


def test_actual_usage_cost_is_separate_from_reservation(tmp_path: Path) -> None:
    result = _generate(tmp_path, QueueProvider(_response()))
    expected = Decimal(100) * INPUT_USD_PER_MILLION_TOKENS / Decimal(1_000_000)
    expected += Decimal(200) * OUTPUT_USD_PER_MILLION_TOKENS / Decimal(1_000_000)

    assert result.evidence.actual_input_tokens == 100
    assert result.evidence.actual_output_tokens == 200
    assert result.evidence.actual_total_tokens == 300
    assert result.evidence.actual_estimated_cost_usd == expected
    assert calculate_actual_cost(result.corpus.generation_metadata.token_usage) == expected
    assert result.evidence.reserved_maximum_cost_usd > expected


@pytest.mark.parametrize("count", [12, 20])
def test_valid_response_persists_c1_verified_corpus(tmp_path: Path, count: int) -> None:
    result = _generate(
        tmp_path,
        QueueProvider(_response(count=count, model=OPENAI_MODEL)),
        count=count,
    )
    loaded = load_corpus(result.path)
    metadata = loaded.generation_metadata

    assert loaded == result.corpus
    assert loaded.corpus_sha256 == result.corpus.corpus_sha256
    assert len(loaded.cases) == count
    assert {case.attack_class for case in loaded.cases} == set(ATTACK_CLASSES)
    assert metadata.openai_response_id == "resp_synthetic_c2"
    assert metadata.model == OPENAI_MODEL == "gpt-5.6-sol"
    assert metadata.prompt_sha256 == build_generation_prompt(count).sha256
    assert metadata.output_schema_version == CORPUS_SCHEMA_VERSION
    assert metadata.generation_timestamp == "2026-07-18T12:34:56Z"
    assert metadata.requested_case_count == metadata.generated_case_count == count
    assert metadata.token_usage == generation.TokenUsage(100, 200, 300)


def test_absent_usage_persists_null_and_returns_no_actual_cost(tmp_path: Path) -> None:
    result = _generate(tmp_path, QueueProvider(_response(usage=None)))

    assert result.corpus.generation_metadata.token_usage is None
    assert result.evidence.actual_input_tokens is None
    assert result.evidence.actual_output_tokens is None
    assert result.evidence.actual_total_tokens is None
    assert result.evidence.actual_estimated_cost_usd is None


def _invalid_local_payload_response() -> ProviderResponse:
    cases = _cases()
    cases[0]["attack_class"] = "unauthorized"
    return _response(output_text=json.dumps({"cases": cases}))


@pytest.mark.parametrize(
    "invalid",
    [
        _response(output_text="not-json"),
        _invalid_local_payload_response(),
        _response(status="incomplete", incomplete_reason="max_output_tokens"),
        _response(refusal=True),
    ],
)
def test_invalid_response_then_valid_response_retries(
    tmp_path: Path, invalid: ProviderResponse
) -> None:
    provider = QueueProvider(invalid, _response())

    result = _generate(tmp_path, provider)

    assert len(provider.calls) == 2
    assert result.evidence.attempts_consumed == 2


def test_known_usage_is_aggregated_across_validation_retry(tmp_path: Path) -> None:
    provider = QueueProvider(_response(output_text="not-json"), _response())
    state = BudgetState()

    result = _generate(tmp_path, provider, state=state)

    assert result.corpus.generation_metadata.token_usage == generation.TokenUsage(100, 200, 300)
    assert result.evidence.actual_input_tokens == 200
    assert result.evidence.actual_output_tokens == 400
    assert result.evidence.actual_total_tokens == 600
    assert result.evidence.actual_estimated_cost_usd == calculate_actual_cost(
        generation.TokenUsage(200, 400, 600)
    )
    assert state.usage_reports_observed == 2
    assert state.known_input_tokens == 200
    assert state.known_output_tokens == 400
    assert state.known_total_tokens == 600
    assert state.known_actual_cost_usd == result.evidence.actual_estimated_cost_usd


def test_two_invalid_structured_outputs_exhaust_retry_without_artifact(tmp_path: Path) -> None:
    provider = QueueProvider(
        _response(output_text="invalid-one"),
        _response(output_text="invalid-two"),
        _response(),
    )

    with pytest.raises(GenerationError) as exc_info:
        _generate(tmp_path, provider)

    assert exc_info.value.code == "response_invalid_json"
    assert len(provider.calls) == 2
    assert not (tmp_path / "corpus.json").exists()


def test_terminal_failure_retains_one_known_usage_report(tmp_path: Path) -> None:
    state = BudgetState()
    provider = QueueProvider(
        _response(output_text="invalid-one", usage=ProviderUsage(10, 20, 30)),
        _response(output_text="invalid-two", usage=None),
    )

    with pytest.raises(GenerationError) as exc_info:
        _generate(tmp_path, provider, state=state)

    assert exc_info.value.code == "response_invalid_json"
    assert len(provider.calls) == 2
    assert state.attempts_consumed == 2
    assert state.reserved_cost_usd == _reservation() * 2
    assert state.usage_reports_observed == 1
    assert state.known_input_tokens == 10
    assert state.known_output_tokens == 20
    assert state.known_total_tokens == 30
    assert state.known_actual_cost_usd == calculate_actual_cost(
        generation.TokenUsage(10, 20, 30)
    )
    validate_budget_state(state)
    assert not (tmp_path / "corpus.json").exists()


def test_two_invalid_responses_retain_both_known_usage_reports(tmp_path: Path) -> None:
    state = BudgetState()
    provider = QueueProvider(
        _response(output_text="invalid-one", usage=ProviderUsage(10, 20, 30)),
        _response(output_text="invalid-two", usage=ProviderUsage(11, 21, 32)),
    )

    with pytest.raises(GenerationError) as exc_info:
        _generate(tmp_path, provider, state=state)

    assert exc_info.value.code == "response_invalid_json"
    assert len(provider.calls) == 2
    assert state.usage_reports_observed == 2
    assert state.known_input_tokens == 21
    assert state.known_output_tokens == 41
    assert state.known_total_tokens == 62
    assert state.known_actual_cost_usd == calculate_actual_cost(
        generation.TokenUsage(21, 41, 62)
    )
    assert not (tmp_path / "corpus.json").exists()


def test_provider_failure_then_invalid_response_exhausts_retry(tmp_path: Path) -> None:
    provider = QueueProvider(
        GenerationError("provider_timeout", retryable=True),
        _response(output_text="invalid"),
    )

    with pytest.raises(GenerationError) as exc_info:
        _generate(tmp_path, provider)

    assert exc_info.value.code == "response_invalid_json"
    assert len(provider.calls) == 2
    assert not (tmp_path / "corpus.json").exists()


def test_provider_failure_then_invalid_response_retains_only_observed_usage(
    tmp_path: Path,
) -> None:
    state = BudgetState()
    provider = QueueProvider(
        GenerationError("provider_timeout", retryable=True),
        _response(output_text="invalid", usage=ProviderUsage(7, 8, 15)),
    )

    with pytest.raises(GenerationError) as exc_info:
        _generate(tmp_path, provider, state=state)

    assert exc_info.value.code == "response_invalid_json"
    assert len(provider.calls) == 2
    assert state.usage_reports_observed == 1
    assert state.known_input_tokens == 7
    assert state.known_output_tokens == 8
    assert state.known_total_tokens == 15
    assert state.known_actual_cost_usd == calculate_actual_cost(
        generation.TokenUsage(7, 8, 15)
    )
    assert not (tmp_path / "corpus.json").exists()


def test_terminal_failures_with_absent_usage_invent_no_evidence(tmp_path: Path) -> None:
    state = BudgetState()
    provider = QueueProvider(
        _response(output_text="invalid-one", usage=None),
        _response(output_text="invalid-two", usage=None),
    )

    with pytest.raises(GenerationError):
        _generate(tmp_path, provider, state=state)

    assert len(provider.calls) == 2
    assert state.usage_reports_observed == 0
    assert state.known_input_tokens == 0
    assert state.known_output_tokens == 0
    assert state.known_total_tokens == 0
    assert state.known_actual_cost_usd == 0
    assert not (tmp_path / "corpus.json").exists()


@pytest.mark.parametrize(
    "code",
    [
        "provider_authentication",
        "provider_permission",
        "provider_bad_request",
        "provider_not_found",
        "provider_unprocessable",
    ],
)
def test_nonretryable_provider_error_makes_one_call(tmp_path: Path, code: str) -> None:
    provider = QueueProvider(GenerationError(code))

    with pytest.raises(GenerationError) as exc_info:
        _generate(tmp_path, provider)

    assert exc_info.value.code == code
    assert len(provider.calls) == 1
    assert not (tmp_path / "corpus.json").exists()


def test_unexpected_provider_exception_has_no_raw_context(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    provider = QueueProvider(RuntimeError(SECRET_MARKER))

    with pytest.raises(GenerationError) as exc_info:
        _generate(tmp_path, provider)

    captured = capsys.readouterr()
    assert exc_info.value.code == "provider_error"
    assert exc_info.value.__cause__ is None
    assert exc_info.value.__context__ is None
    assert SECRET_MARKER not in str(exc_info.value)
    assert SECRET_MARKER not in captured.out
    assert SECRET_MARKER not in captured.err


@pytest.mark.parametrize(
    ("response", "code"),
    [
        (replace(_response(), response_id=None), "response_missing_id"),
        (replace(_response(), model=None), "response_missing_model"),
        (_response(model="gpt-5.6"), "response_model_mismatch"),
        (_response(model="gpt-5.6-terra"), "response_model_mismatch"),
        (_response(model="gpt-5.6-luna"), "response_model_mismatch"),
        (_response(status="failed"), "response_status"),
        (_response(status="cancelled"), "response_status"),
        (_response(error_category="response_error"), "response_error"),
        (_response(output_text=""), "response_missing_output"),
        (_response(output_text="[]"), "response_invalid_shape"),
        (_response(output_text=json.dumps({"cases": _cases(), "extra": True})), "response_invalid_shape"),
        (_response(usage=ProviderUsage(True, 2, 3)), "response_invalid_usage"),
        (_response(usage=ProviderUsage(1, 2, 4)), "response_invalid_usage"),
    ],
)
def test_invalid_response_categories_are_sanitized_and_bounded(
    tmp_path: Path, response: ProviderResponse, code: str
) -> None:
    provider = QueueProvider(response, response)

    with pytest.raises(GenerationError) as exc_info:
        _generate(tmp_path, provider)

    assert exc_info.value.code == code
    assert len(provider.calls) == 2
    assert not (tmp_path / "corpus.json").exists()


@pytest.mark.parametrize(
    "service_tier",
    [None, True, "auto", "priority", "flex", "scale", "unknown-" + SECRET_MARKER],
)
def test_service_tier_mismatch_is_nonretryable_and_persists_nothing(
    tmp_path: Path,
    service_tier: object,
    capsys: pytest.CaptureFixture[str],
) -> None:
    provider = QueueProvider(_response(service_tier=service_tier), _response())

    with pytest.raises(GenerationError) as exc_info:
        _generate(tmp_path, provider)

    captured = capsys.readouterr()
    assert exc_info.value.code == "response_service_tier_mismatch"
    assert exc_info.value.retryable is False
    assert SECRET_MARKER not in str(exc_info.value)
    assert SECRET_MARKER not in captured.out
    assert SECRET_MARKER not in captured.err
    assert len(provider.calls) == 1
    assert not (tmp_path / "corpus.json").exists()


def test_missing_service_tier_prevents_retry_even_when_identity_is_missing(
    tmp_path: Path,
) -> None:
    provider = QueueProvider(
        _response(response_id=None, service_tier=None),  # type: ignore[arg-type]
        _response(),
    )

    with pytest.raises(GenerationError) as exc_info:
        _generate(tmp_path, provider)

    assert exc_info.value.code == "response_service_tier_mismatch"
    assert len(provider.calls) == 1


def test_invalid_utf8_text_representation_is_rejected(tmp_path: Path) -> None:
    response = _response(output_text="\ud800")
    provider = QueueProvider(response, response)

    with pytest.raises(GenerationError) as exc_info:
        _generate(tmp_path, provider)

    assert exc_info.value.code == "response_invalid_utf8"
    assert len(provider.calls) == 2


def test_local_bounds_failure_makes_zero_calls(tmp_path: Path) -> None:
    provider = QueueProvider(_response())

    with pytest.raises(GenerationError):
        _generate(tmp_path, provider, count=11)

    assert provider.calls == []


def test_persistence_failure_is_not_retried(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    provider = QueueProvider(_response(), _response())
    state = BudgetState()

    def fail_persistence(_corpus: object, _path: object) -> object:
        raise CorpusValidationError(SECRET_MARKER)

    monkeypatch.setattr(generation, "persist_corpus", fail_persistence)
    with pytest.raises(GenerationError) as exc_info:
        _generate(tmp_path, provider, state=state)

    assert exc_info.value.code == "persistence_failed"
    assert str(exc_info.value) == "Generated corpus persistence failed."
    assert exc_info.value.__cause__ is None
    assert exc_info.value.__context__ is None
    assert len(provider.calls) == 1
    assert state.attempts_consumed == 1
    assert state.usage_reports_observed == 1
    assert state.known_input_tokens == 100
    assert state.known_output_tokens == 200
    assert state.known_total_tokens == 300
    assert state.known_actual_cost_usd == calculate_actual_cost(
        generation.TokenUsage(100, 200, 300)
    )
    assert not (tmp_path / "corpus.json").exists()


def test_existing_destination_is_rejected_before_provider_call(tmp_path: Path) -> None:
    path = tmp_path / "corpus.json"
    path.write_bytes(b"existing\n")
    provider = QueueProvider(_response(), _response())
    state = BudgetState()

    with pytest.raises(GenerationError) as exc_info:
        _generate(tmp_path, provider, state=state)

    assert exc_info.value.code == "destination_exists"
    assert provider.calls == []
    assert state.attempts_consumed == 0
    assert state.reserved_cost_usd == 0
    assert path.read_bytes() == b"existing\n"


@pytest.mark.parametrize("kind", ["file", "directory", "dangling_symlink"])
def test_existing_destination_kinds_fail_preflight_without_spend(
    tmp_path: Path,
    kind: str,
) -> None:
    path = tmp_path / "destination"
    if kind == "file":
        path.write_text("existing", encoding="utf-8")
    elif kind == "directory":
        path.mkdir()
    else:
        path.symlink_to(tmp_path / "missing-target")
    provider = QueueProvider(_response())
    state = BudgetState()

    with pytest.raises(GenerationError) as exc_info:
        _generate(tmp_path, provider, state=state, path=path)

    assert exc_info.value.code == "destination_exists"
    assert provider.calls == []
    assert state.attempts_consumed == 0
    assert state.reserved_cost_usd == 0


@pytest.mark.parametrize("path", [b"corpus.json", "", "invalid\0path"])
def test_invalid_destination_values_fail_preflight_without_spend(
    tmp_path: Path,
    path: object,
) -> None:
    provider = QueueProvider(_response())
    state = BudgetState()

    with pytest.raises(GenerationError) as exc_info:
        _generate(tmp_path, provider, state=state, path=path)

    assert exc_info.value.code == "destination_invalid"
    assert provider.calls == []
    assert state.attempts_consumed == 0
    assert state.reserved_cost_usd == 0


def test_hostile_pathlike_error_is_sanitized_and_spends_nothing(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    class HostilePath:
        def __fspath__(self) -> str:
            raise RuntimeError(SECRET_MARKER)

    provider = QueueProvider(_response())
    state = BudgetState()

    with pytest.raises(GenerationError) as exc_info:
        _generate(tmp_path, provider, state=state, path=HostilePath())

    captured = capsys.readouterr()
    assert exc_info.value.code == "destination_invalid"
    assert exc_info.value.__cause__ is None
    assert exc_info.value.__context__ is None
    assert SECRET_MARKER not in str(exc_info.value)
    assert SECRET_MARKER not in captured.out
    assert SECRET_MARKER not in captured.err
    assert provider.calls == []
    assert state.attempts_consumed == 0


def test_destination_pathlike_is_resolved_once(tmp_path: Path) -> None:
    class CountingPath:
        def __init__(self, value: str) -> None:
            self.value = value
            self.calls = 0

        def __fspath__(self) -> str:
            self.calls += 1
            return self.value

    path = CountingPath(str(tmp_path / "corpus.json"))

    result = _generate(tmp_path, QueueProvider(_response()), path=path)

    assert path.calls == 1
    assert result.path == tmp_path / "corpus.json"


def test_existing_non_directory_ancestor_fails_preflight_without_spend(
    tmp_path: Path,
) -> None:
    parent_file = tmp_path / "parent"
    parent_file.write_text("not a directory", encoding="utf-8")
    provider = QueueProvider(_response())
    state = BudgetState()

    with pytest.raises(GenerationError) as exc_info:
        _generate(
            tmp_path,
            provider,
            state=state,
            path=parent_file / "nested" / "corpus.json",
        )

    assert exc_info.value.code == "destination_invalid"
    assert provider.calls == []
    assert state.attempts_consumed == 0
    assert state.reserved_cost_usd == 0


@pytest.mark.parametrize("access_result", [False, None])
def test_destination_permission_preflight_requires_effective_write_and_search_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    access_result: object,
) -> None:
    access_calls: list[tuple[object, int, bool]] = []

    def access(
        path: object,
        mode: int,
        *,
        effective_ids: bool = False,
    ) -> object:
        access_calls.append((path, mode, effective_ids))
        return access_result

    monkeypatch.setattr(generation.os, "access", access)
    monkeypatch.setattr(generation.os, "supports_effective_ids", {access})
    path = tmp_path / "nested" / "corpus.json"
    provider = QueueProvider(_response())
    state = BudgetState()

    with pytest.raises(GenerationError) as exc_info:
        _generate(tmp_path, provider, state=state, path=path)

    assert exc_info.value.code == "destination_invalid"
    assert access_calls == [(tmp_path, os.W_OK | os.X_OK, True)]
    assert provider.calls == []
    assert state.attempts_consumed == 0
    assert state.reserved_cost_usd == 0
    assert not path.exists()


def test_destination_permission_check_exception_is_sanitized_before_spend(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def hostile_access(
        _path: object,
        _mode: int,
        *,
        effective_ids: bool = False,
    ) -> bool:
        assert effective_ids is True
        raise OSError(SECRET_MARKER)

    monkeypatch.setattr(generation.os, "access", hostile_access)
    monkeypatch.setattr(generation.os, "supports_effective_ids", {hostile_access})
    path = tmp_path / "nested" / "corpus.json"
    provider = QueueProvider(_response())
    state = BudgetState()

    with pytest.raises(GenerationError) as exc_info:
        _generate(tmp_path, provider, state=state, path=path)

    captured = capsys.readouterr()
    assert exc_info.value.code == "destination_invalid"
    assert exc_info.value.__cause__ is None
    assert exc_info.value.__context__ is None
    assert SECRET_MARKER not in str(exc_info.value)
    assert SECRET_MARKER not in captured.out
    assert SECRET_MARKER not in captured.err
    assert provider.calls == []
    assert state.attempts_consumed == 0
    assert state.reserved_cost_usd == 0
    assert not path.exists()


def test_writable_ancestor_supports_missing_nested_parents(tmp_path: Path) -> None:
    path = tmp_path / "one" / "two" / "corpus.json"
    provider = QueueProvider(_response())

    result = _generate(tmp_path, provider, path=path)

    assert len(provider.calls) == 1
    assert result.path == path
    assert path.exists()


def test_destination_access_check_falls_back_without_effective_id_support(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    access_calls: list[tuple[object, int]] = []

    def access(path: object, mode: int) -> bool:
        access_calls.append((path, mode))
        return True

    monkeypatch.setattr(generation.os, "access", access)
    monkeypatch.setattr(generation.os, "supports_effective_ids", set())
    path = tmp_path / "nested" / "corpus.json"

    result = _generate(tmp_path, QueueProvider(_response()), path=path)

    assert access_calls == [(tmp_path, os.W_OK | os.X_OK)]
    assert result.path == path
    assert path.exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission modes are required")
@pytest.mark.parametrize("mode", [0o500, 0o600], ids=["no_write", "no_search"])
def test_posix_permission_denied_destination_fails_before_spend(
    tmp_path: Path,
    mode: int,
) -> None:
    locked = tmp_path / "locked"
    path = locked / "corpus.json"
    locked.mkdir()
    locked.chmod(mode)
    try:
        access_kwargs = (
            {"effective_ids": True}
            if os.access in os.supports_effective_ids
            else {}
        )
        if os.access(locked, os.W_OK | os.X_OK, **access_kwargs):
            pytest.skip(
                f"effective identity retains creation access beneath mode-{mode:o} directory"
            )
        provider = QueueProvider(_response())
        state = BudgetState()

        with pytest.raises(GenerationError) as exc_info:
            _generate(tmp_path, provider, state=state, path=path)

        assert exc_info.value.code == "destination_invalid"
        assert provider.calls == []
        assert state.attempts_consumed == 0
        assert state.reserved_cost_usd == 0
    finally:
        locked.chmod(0o700)
    assert not path.exists()


@pytest.mark.parametrize(
    "clock",
    [
        lambda: datetime(2026, 7, 18, 12, 34, 56),
        lambda: "not-a-datetime",
    ],
)
def test_invalid_clock_values_fail_preflight_without_spend(
    tmp_path: Path,
    clock: Callable[[], object],
) -> None:
    provider = QueueProvider(_response())
    state = BudgetState()

    with pytest.raises(GenerationError) as exc_info:
        _generate(tmp_path, provider, state=state, clock=clock)

    assert exc_info.value.code == "clock_invalid"
    assert provider.calls == []
    assert state.attempts_consumed == 0
    assert state.reserved_cost_usd == 0


def test_clock_exception_is_sanitized_and_spends_nothing(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def hostile_clock() -> datetime:
        raise RuntimeError(SECRET_MARKER)

    provider = QueueProvider(_response())
    state = BudgetState()

    with pytest.raises(GenerationError) as exc_info:
        _generate(tmp_path, provider, state=state, clock=hostile_clock)

    captured = capsys.readouterr()
    assert exc_info.value.code == "clock_invalid"
    assert exc_info.value.__cause__ is None
    assert exc_info.value.__context__ is None
    assert SECRET_MARKER not in str(exc_info.value)
    assert SECRET_MARKER not in captured.out
    assert SECRET_MARKER not in captured.err
    assert provider.calls == []
    assert state.attempts_consumed == 0


def test_valid_clock_is_called_once_and_reused_for_metadata(tmp_path: Path) -> None:
    calls = 0

    def clock() -> datetime:
        nonlocal calls
        calls += 1
        return FIXED_TIME

    result = _generate(tmp_path, QueueProvider(_response()), clock=clock)

    assert calls == 1
    assert result.corpus.generation_metadata.generation_timestamp == "2026-07-18T12:34:56Z"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (datetime(1, 1, 1, tzinfo=timezone.utc), "0001-01-01T00:00:00Z"),
        (datetime(999, 12, 31, 23, 59, 59, tzinfo=timezone.utc), "0999-12-31T23:59:59Z"),
    ],
)
def test_early_year_clock_is_canonical_through_c1_reload(
    tmp_path: Path,
    value: datetime,
    expected: str,
) -> None:
    calls = 0

    def clock() -> datetime:
        nonlocal calls
        calls += 1
        return value

    provider = QueueProvider(_response())
    result = _generate(tmp_path, provider, clock=clock)
    reloaded = load_corpus(result.path)

    assert calls == 1
    assert len(provider.calls) == 1
    assert len(expected) == 20
    assert expected.isascii()
    assert result.corpus.generation_metadata.generation_timestamp == expected
    assert reloaded.generation_metadata.generation_timestamp == expected


def test_non_utc_clock_is_converted_once_to_canonical_utc(tmp_path: Path) -> None:
    conversions = 0

    class CountingDatetime(datetime):
        def astimezone(self, tz: object = None) -> datetime:
            nonlocal conversions
            conversions += 1
            return super().astimezone(tz)  # type: ignore[arg-type]

    source = CountingDatetime(
        2026,
        1,
        1,
        5,
        30,
        7,
        tzinfo=timezone(timedelta(hours=5, minutes=30)),
    )

    result = _generate(tmp_path, QueueProvider(_response()), clock=lambda: source)

    assert conversions == 1
    assert result.corpus.generation_metadata.generation_timestamp == "2026-01-01T00:00:07Z"


def test_timezone_conversion_failure_is_sanitized_before_spend(tmp_path: Path) -> None:
    class HostileDatetime(datetime):
        def astimezone(self, _tz: object = None) -> datetime:
            raise RuntimeError(SECRET_MARKER)

    provider = QueueProvider(_response())
    state = BudgetState()
    value = HostileDatetime(2026, 7, 18, 12, 34, 56, tzinfo=timezone.utc)

    with pytest.raises(GenerationError) as exc_info:
        _generate(tmp_path, provider, state=state, clock=lambda: value)

    assert exc_info.value.code == "clock_invalid"
    assert exc_info.value.__cause__ is None
    assert exc_info.value.__context__ is None
    assert SECRET_MARKER not in str(exc_info.value)
    assert provider.calls == []
    assert state.attempts_consumed == 0
    assert state.reserved_cost_usd == 0


def test_non_datetime_utc_conversion_result_fails_before_spend(
    tmp_path: Path,
) -> None:
    clock_calls = 0
    conversions = 0
    converted = object()

    class SourceDatetime(datetime):
        def astimezone(self, _tz: object = None) -> object:
            nonlocal conversions
            conversions += 1
            return converted

    value = SourceDatetime(2026, 7, 18, 12, 34, 56, tzinfo=timezone.utc)

    def clock() -> datetime:
        nonlocal clock_calls
        clock_calls += 1
        return value

    provider = QueueProvider(_response())
    state = BudgetState()
    with pytest.raises(GenerationError) as exc_info:
        _generate(tmp_path, provider, state=state, clock=clock)

    assert exc_info.value.code == "clock_invalid"
    assert exc_info.value.__cause__ is None
    assert exc_info.value.__context__ is None
    assert clock_calls == 1
    assert conversions == 1
    assert provider.calls == []
    assert state.attempts_consumed == 0
    assert state.reserved_cost_usd == 0


@pytest.mark.parametrize(
    "kind",
    ["invalid_month", "invalid_day", "nonzero_offset", "property_error", "offset_error"],
)
def test_hostile_datetime_utc_conversion_result_fails_before_spend(
    tmp_path: Path,
    kind: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    class InvalidMonth(datetime):
        @property
        def month(self) -> int:
            return 13

    class InvalidDay(datetime):
        @property
        def day(self) -> int:
            return 0

    class InvalidOffset(datetime):
        def utcoffset(self) -> timedelta:
            return timedelta(hours=1)

    class HostileProperty(datetime):
        @property
        def year(self) -> int:
            raise RuntimeError(SECRET_MARKER)

    class HostileOffset(datetime):
        def utcoffset(self) -> timedelta:
            raise RuntimeError(SECRET_MARKER)

    converted_values = {
        "invalid_month": InvalidMonth(2026, 7, 18, 12, 34, 56, tzinfo=timezone.utc),
        "invalid_day": InvalidDay(2026, 7, 18, 12, 34, 56, tzinfo=timezone.utc),
        "nonzero_offset": InvalidOffset(2026, 7, 18, 12, 34, 56, tzinfo=timezone.utc),
        "property_error": HostileProperty(2026, 7, 18, 12, 34, 56, tzinfo=timezone.utc),
        "offset_error": HostileOffset(2026, 7, 18, 12, 34, 56, tzinfo=timezone.utc),
    }
    clock_calls = 0
    conversions = 0

    class SourceDatetime(datetime):
        def astimezone(self, _tz: object = None) -> datetime:
            nonlocal conversions
            conversions += 1
            return converted_values[kind]

    value = SourceDatetime(2026, 7, 18, 12, 34, 56, tzinfo=timezone.utc)

    def clock() -> datetime:
        nonlocal clock_calls
        clock_calls += 1
        return value

    provider = QueueProvider(_response())
    state = BudgetState()
    with pytest.raises(GenerationError) as exc_info:
        _generate(tmp_path, provider, state=state, clock=clock)

    captured = capsys.readouterr()
    assert exc_info.value.code == "clock_invalid"
    assert exc_info.value.__cause__ is None
    assert exc_info.value.__context__ is None
    assert SECRET_MARKER not in str(exc_info.value)
    assert SECRET_MARKER not in captured.out
    assert SECRET_MARKER not in captured.err
    assert clock_calls == 1
    assert conversions == 1
    assert provider.calls == []
    assert state.attempts_consumed == 0
    assert state.reserved_cost_usd == 0


def test_destination_race_is_not_retried_and_retains_known_usage(tmp_path: Path) -> None:
    path = tmp_path / "corpus.json"

    class RaceProvider(QueueProvider):
        def create_response(self, request: generation.GenerationRequest) -> ProviderResponse:
            path.write_bytes(b"race-winner\n")
            return super().create_response(request)

    provider = RaceProvider(_response(), _response())
    state = BudgetState()

    with pytest.raises(GenerationError) as exc_info:
        _generate(tmp_path, provider, state=state, path=path)

    assert exc_info.value.code == "persistence_failed"
    assert len(provider.calls) == 1
    assert state.attempts_consumed == 1
    assert state.usage_reports_observed == 1
    assert state.known_input_tokens == 100
    assert state.known_output_tokens == 200
    assert state.known_total_tokens == 300
    assert state.known_actual_cost_usd == calculate_actual_cost(
        generation.TokenUsage(100, 200, 300)
    )
    assert path.read_bytes() == b"race-winner\n"


def test_post_preflight_permission_race_is_sanitized_without_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "corpus.json"
    provider = QueueProvider(_response(), _response())
    state = BudgetState()

    def deny_persistence(_corpus: object, _path: object) -> object:
        raise PermissionError(SECRET_MARKER)

    monkeypatch.setattr(generation, "persist_corpus", deny_persistence)
    with pytest.raises(GenerationError) as exc_info:
        _generate(tmp_path, provider, state=state, path=path)

    captured = capsys.readouterr()
    assert exc_info.value.code == "persistence_failed"
    assert exc_info.value.__cause__ is None
    assert exc_info.value.__context__ is None
    assert SECRET_MARKER not in str(exc_info.value)
    assert SECRET_MARKER not in captured.out
    assert SECRET_MARKER not in captured.err
    assert len(provider.calls) == 1
    assert state.attempts_consumed == 1
    assert state.usage_reports_observed == 1
    assert state.known_input_tokens == 100
    assert state.known_output_tokens == 200
    assert state.known_total_tokens == 300
    assert state.known_actual_cost_usd == calculate_actual_cost(
        generation.TokenUsage(100, 200, 300)
    )
    assert not path.exists()


def test_project_usage_is_cumulative_but_success_evidence_is_operation_local(
    tmp_path: Path,
) -> None:
    state = BudgetState()
    failed = QueueProvider(
        _response(output_text="invalid-one", usage=ProviderUsage(10, 20, 30)),
        _response(output_text="invalid-two", usage=ProviderUsage(11, 21, 32)),
    )
    with pytest.raises(GenerationError):
        _generate(tmp_path, failed, state=state, name="failed.json")

    result = _generate(
        tmp_path,
        QueueProvider(_response(usage=ProviderUsage(100, 200, 300))),
        state=state,
        name="success.json",
    )

    assert result.evidence.attempts_consumed == 1
    assert result.evidence.actual_input_tokens == 100
    assert result.evidence.actual_output_tokens == 200
    assert result.evidence.actual_total_tokens == 300
    assert result.evidence.actual_estimated_cost_usd == calculate_actual_cost(
        generation.TokenUsage(100, 200, 300)
    )
    assert state.attempts_consumed == 3
    assert state.usage_reports_observed == 3
    assert state.known_input_tokens == 121
    assert state.known_output_tokens == 241
    assert state.known_total_tokens == 362
    assert state.known_actual_cost_usd == calculate_actual_cost(
        generation.TokenUsage(121, 241, 362)
    )


def test_over_limit_usage_retries_then_records_only_valid_usage(tmp_path: Path) -> None:
    invalid = ProviderUsage(0, MAX_OUTPUT_TOKENS + 1, MAX_OUTPUT_TOKENS + 1)
    valid = ProviderUsage(10, 20, 30)
    provider = QueueProvider(_response(usage=invalid), _response(usage=valid))
    state = BudgetState()

    result = _generate(
        tmp_path,
        provider,
        max_output_tokens=MAX_OUTPUT_TOKENS,
        state=state,
    )

    assert len(provider.calls) == 2
    assert state.attempts_consumed == 2
    assert state.reserved_cost_usd == _reservation(output_tokens=MAX_OUTPUT_TOKENS) * 2
    assert state.usage_reports_observed == 1
    assert state.known_input_tokens == 10
    assert state.known_output_tokens == 20
    assert state.known_total_tokens == 30
    assert state.known_actual_cost_usd == calculate_actual_cost(
        generation.TokenUsage(10, 20, 30)
    )
    assert result.corpus.generation_metadata.token_usage == generation.TokenUsage(10, 20, 30)


def test_two_over_limit_usage_reports_exhaust_retry_without_ledger_mutation(
    tmp_path: Path,
) -> None:
    invalid = ProviderUsage(0, MAX_OUTPUT_TOKENS + 1, MAX_OUTPUT_TOKENS + 1)
    provider = QueueProvider(_response(usage=invalid), _response(usage=invalid))
    state = BudgetState()

    with pytest.raises(GenerationError) as exc_info:
        _generate(
            tmp_path,
            provider,
            max_output_tokens=MAX_OUTPUT_TOKENS,
            state=state,
        )

    assert exc_info.value.code == "response_invalid_usage"
    assert len(provider.calls) == 2
    assert state.attempts_consumed == 2
    assert state.reserved_cost_usd == _reservation(output_tokens=MAX_OUTPUT_TOKENS) * 2
    assert state.usage_reports_observed == 0
    assert state.known_input_tokens == 0
    assert state.known_output_tokens == 0
    assert state.known_total_tokens == 0
    assert state.known_actual_cost_usd == 0
    assert not (tmp_path / "corpus.json").exists()


def test_input_usage_above_reserved_bound_never_enters_ledger(tmp_path: Path) -> None:
    input_bound, reservation = _reservation_details()
    invalid = ProviderUsage(input_bound + 1, 0, input_bound + 1)
    provider = QueueProvider(_response(usage=invalid), _response(usage=invalid))
    state = BudgetState()

    with pytest.raises(GenerationError) as exc_info:
        _generate(tmp_path, provider, state=state)

    assert exc_info.value.code == "response_invalid_usage"
    assert len(provider.calls) == 2
    assert state.attempts_consumed == 2
    assert state.reserved_cost_usd == reservation * 2
    assert state.usage_reports_observed == 0
    assert state.known_input_tokens == 0
    assert state.known_output_tokens == 0
    assert state.known_total_tokens == 0
    assert state.known_actual_cost_usd == 0
    assert not (tmp_path / "corpus.json").exists()


def test_usage_cost_above_attempt_reservation_is_rejected() -> None:
    with pytest.raises(GenerationError) as exc_info:
        generation._validate_usage(
            ProviderUsage(1, 1, 2),
            input_token_upper_bound=1,
            max_output_tokens=1,
            reserved_cost_usd=Decimal("0"),
        )

    assert exc_info.value.code == "response_invalid_usage"


def test_extreme_impossible_usage_never_enters_project_state(tmp_path: Path) -> None:
    invalid = ProviderUsage(1_000_000_000, 1_000_000_000, 2_000_000_000)
    provider = QueueProvider(_response(usage=invalid), _response(usage=invalid))
    state = BudgetState()

    with pytest.raises(GenerationError) as exc_info:
        _generate(tmp_path, provider, state=state)

    assert exc_info.value.code == "response_invalid_usage"
    assert len(provider.calls) == 2
    assert state.attempts_consumed == 2
    assert state.reserved_cost_usd == _reservation() * 2
    assert state.usage_reports_observed == 0
    assert state.known_input_tokens == 0
    assert state.known_output_tokens == 0
    assert state.known_total_tokens == 0
    assert state.known_actual_cost_usd == 0
    assert state.known_actual_cost_usd != Decimal("35000")
    assert not (tmp_path / "corpus.json").exists()


def test_usage_at_exact_request_bounds_is_accepted(tmp_path: Path) -> None:
    input_bound, reservation = _reservation_details(output_tokens=MAX_OUTPUT_TOKENS)
    usage = ProviderUsage(
        input_bound,
        MAX_OUTPUT_TOKENS,
        input_bound + MAX_OUTPUT_TOKENS,
    )
    with localcontext(Context(prec=50, rounding=ROUND_CEILING)):
        expected_cost = (
            Decimal(input_bound) * Decimal("5.00") / Decimal("1000000")
            + Decimal(MAX_OUTPUT_TOKENS) * Decimal("30.00") / Decimal("1000000")
        )

    result = _generate(
        tmp_path,
        QueueProvider(_response(usage=usage)),
        max_output_tokens=MAX_OUTPUT_TOKENS,
    )

    assert expected_cost <= reservation
    assert result.corpus.generation_metadata.token_usage == generation.TokenUsage(
        usage.input_tokens,
        usage.output_tokens,
        usage.total_tokens,
    )
    assert result.evidence.actual_estimated_cost_usd == expected_cost


def test_budget_state_rejects_known_cost_above_reserved_cost() -> None:
    minimum_reservation, _ = _supported_reservation_bounds_oracle()
    usage = generation.TokenUsage(0, MAX_OUTPUT_TOKENS, MAX_OUTPUT_TOKENS)
    known_cost = calculate_actual_cost(usage)
    assert known_cost > minimum_reservation
    state = BudgetState(
        attempts_consumed=1,
        reserved_cost_usd=minimum_reservation,
        usage_reports_observed=1,
        known_output_tokens=usage.output_tokens,
        known_total_tokens=usage.total_tokens,
        known_actual_cost_usd=known_cost,
    )

    with pytest.raises(GenerationError) as exc_info:
        validate_budget_state(state)

    assert exc_info.value.code == "invalid_configuration"


def test_secret_marker_in_malformed_output_never_escapes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    malformed = _response(output_text="{" + SECRET_MARKER)
    provider = QueueProvider(malformed, malformed)

    with pytest.raises(GenerationError) as exc_info:
        _generate(tmp_path, provider)

    captured = capsys.readouterr()
    assert SECRET_MARKER not in str(exc_info.value)
    assert exc_info.value.__cause__ is None
    assert exc_info.value.__context__ is None
    assert SECRET_MARKER not in captured.out
    assert SECRET_MARKER not in captured.err
    assert not (tmp_path / "corpus.json").exists()


def test_request_contract_has_no_model_override_tools_or_state(tmp_path: Path) -> None:
    provider = QueueProvider(_response())

    _generate(tmp_path, provider, max_output_tokens=4096)

    request = provider.calls[0]
    assert request.model == OPENAI_MODEL
    assert request.max_output_tokens == 4096
    assert request.text_format["strict"] is True
    assert request.text_format["type"] == "json_schema"
    assert request.input == build_generation_prompt(12).generation_input
    assert request.instructions == build_generation_prompt(12).instructions
