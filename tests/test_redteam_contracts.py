from __future__ import annotations

import json
from importlib import resources
from pathlib import PurePosixPath

import pytest

from llmfuzz.redteam_contracts import (
    CASE_RESULT_SCHEMA_VERSION,
    CASE_VERDICTS,
    EVENT_SCHEMA_VERSION,
    EVENT_TYPES,
    FINAL_DISPOSITIONS,
    INVARIANT_RESULT_SCHEMA_VERSION,
    INVARIANT_STATUSES,
    MAX_EVENT_COUNT,
    MAX_EVENT_NAME_CHARS,
    MAX_EVIDENCE_REF_CHARS,
    MAX_EVIDENCE_REFS,
    PHASE_D_ARTIFACT_LAYOUT,
    TARGET_INPUT_SCHEMA_VERSION,
    CaseResult,
    ContractValidationError,
    InvariantResult,
    ObservedEvent,
    TargetInput,
    canonical_contract_bytes,
    target_input_from_case,
    validate_case_result,
    validate_event,
    validate_invariant_result,
    validate_target_input,
)
from llmfuzz.redteam_corpus import (
    ASSERTION_VOCABULARY,
    ATTACK_CLASSES,
    MAX_INPUT_CHARS,
    CorpusCase,
    load_bundled_accepted_corpus,
    validate_corpus,
)


def _case() -> CorpusCase:
    return load_bundled_accepted_corpus().cases[0]


def _case_with_assertions_container(assertions: object) -> CorpusCase:
    case = _case()
    return CorpusCase(
        schema_version=case.schema_version,
        case_id=case.case_id,
        attack_class=case.attack_class,
        input=case.input,
        expected_risk=case.expected_risk,
        rationale=case.rationale,
        assertions=assertions,  # type: ignore[arg-type]
    )


def _target_input_raw(case: CorpusCase) -> dict[str, object]:
    return {
        "schema_version": TARGET_INPUT_SCHEMA_VERSION,
        "case_id": case.case_id,
        "attack_class": case.attack_class,
        "input": case.input,
        "assertions": list(case.assertions),
    }


def _event(event_type: str, payload: dict[str, object]) -> dict[str, object]:
    return {
        "schema_version": EVENT_SCHEMA_VERSION,
        "event_type": event_type,
        "payload": payload,
    }


def _invariant(
    case: CorpusCase,
    invariant_id: str,
    *,
    status: str = "PASS",
    evidence_refs: list[str] | None = None,
) -> dict[str, object]:
    return {
        "schema_version": INVARIANT_RESULT_SCHEMA_VERSION,
        "invariant_id": invariant_id,
        "status": status,
        "criticality": case.expected_risk,
        "evidence_refs": (
            evidence_refs
            if evidence_refs is not None
            else ["exec/redteam-events.json#0"]
        ),
    }


def _case_result(
    case: CorpusCase,
    *,
    events: list[object] | None = None,
    invariant_results: list[object] | None = None,
    evidence_refs: list[str] | None = None,
    verdict: str = "TIMEOUT",
) -> dict[str, object]:
    return {
        "schema_version": CASE_RESULT_SCHEMA_VERSION,
        "case_id": case.case_id,
        "attack_class": case.attack_class,
        "events": events if events is not None else [],
        "invariant_results": invariant_results if invariant_results is not None else [],
        "evidence_refs": evidence_refs if evidence_refs is not None else [],
        "verdict": verdict,
    }


def _complete_invariant_results(
    case: CorpusCase, *, failing: bool = False
) -> list[dict[str, object]]:
    return [
        _invariant(
            case,
            invariant_id,
            status="FAIL" if failing and index == 0 else "PASS",
            evidence_refs=[f"exec/redteam-events.json#{index}"],
        )
        for index, invariant_id in enumerate(case.assertions)
    ]


def _final_event(disposition: str = "completed") -> dict[str, object]:
    return _event("final", {"disposition": disposition})


def test_target_input_conversion_has_exact_fields_and_canonical_bytes() -> None:
    case = _case()
    target_input = target_input_from_case(case)
    encoded = canonical_contract_bytes(target_input)
    raw = json.loads(encoded)

    assert raw == _target_input_raw(case)
    assert set(raw) == {"schema_version", "case_id", "attack_class", "input", "assertions"}
    assert encoded == (
        json.dumps(raw, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    assert canonical_contract_bytes(validate_target_input(raw)) == encoded


@pytest.mark.parametrize("assertions", [None, ["must_not_follow_untrusted_instruction"]])
def test_public_entrypoints_reject_noncanonical_case_assertion_containers(
    assertions: object,
) -> None:
    case = _case()
    malformed = _case_with_assertions_container(assertions)

    with pytest.raises(ContractValidationError, match="case.assertions.*validated assertion tuple"):
        target_input_from_case(malformed)
    with pytest.raises(ContractValidationError, match="case.assertions.*validated assertion tuple"):
        validate_invariant_result(_invariant(case, case.assertions[0]), malformed)
    with pytest.raises(ContractValidationError, match="case.assertions.*validated assertion tuple"):
        validate_case_result(_case_result(case), malformed)


def test_public_entrypoints_accept_loaded_canonical_case_context() -> None:
    case = _case()

    assert target_input_from_case(case).case_id == case.case_id
    assert (
        validate_invariant_result(_invariant(case, case.assertions[0]), case).invariant_id
        == case.assertions[0]
    )
    assert validate_case_result(_case_result(case), case).case_id == case.case_id


def test_canonical_serialization_rejects_direct_invalid_target_inputs() -> None:
    case = _case()
    invalid_values = (
        TargetInput(
            "unknown",
            case.case_id,
            case.attack_class,
            case.input,
            case.assertions,
        ),
        TargetInput(
            TARGET_INPUT_SCHEMA_VERSION,
            case.case_id,
            case.attack_class,
            case.input,
            ("unknown",),
        ),
    )

    for value in invalid_values:
        with pytest.raises(ContractValidationError):
            canonical_contract_bytes(value)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("schema_version", "unknown", "schema_version"),
        ("attack_class", "unknown", "attack_class"),
        ("input", "x" * (MAX_INPUT_CHARS + 1), "at most"),
        ("assertions", ["unknown"], "unknown assertion"),
    ],
)
def test_target_input_rejects_invalid_fields(field: str, value: object, message: str) -> None:
    raw = _target_input_raw(_case())
    raw[field] = value

    with pytest.raises(ContractValidationError, match=message):
        validate_target_input(raw)


def test_target_input_rejects_unknown_field_and_duplicate_assertions() -> None:
    raw = _target_input_raw(_case())
    raw["unknown"] = True
    with pytest.raises(ContractValidationError, match="unknown field"):
        validate_target_input(raw)

    raw = _target_input_raw(_case())
    raw["assertions"] = [raw["assertions"][0], raw["assertions"][0]]  # type: ignore[index]
    with pytest.raises(ContractValidationError, match="duplicates"):
        validate_target_input(raw)


@pytest.mark.parametrize(
    ("event_type", "payload"),
    [
        ("untrusted_instruction", {"followed": False}),
        ("secret_revelation", {"revealed": False}),
        (
            "tool_call",
            {"tool_name": "synthetic_tool", "forbidden": True, "executed": True},
        ),
        ("approval_check", {"approved": False}),
        ("protected_action", {"action_name": "synthetic_action", "executed": False}),
        ("final", {"disposition": "refused"}),
    ],
)
def test_minimum_event_variants_are_closed_and_stable(
    event_type: str, payload: dict[str, object]
) -> None:
    event = validate_event(_event(event_type, payload))
    raw = json.loads(canonical_contract_bytes(event))

    assert event_type in EVENT_TYPES
    assert raw == _event(event_type, payload)
    assert "timestamp" not in raw
    assert "id" not in raw


@pytest.mark.parametrize("executed", [True, False])
def test_tool_call_locks_forbidden_execution_state_and_canonical_bytes(
    executed: bool,
) -> None:
    event = validate_event(
        _event(
            "tool_call",
            {"executed": executed, "forbidden": True, "tool_name": "synthetic_tool"},
        )
    )

    assert event.payload == (
        ("tool_name", "synthetic_tool"),
        ("forbidden", True),
        ("executed", executed),
    )
    assert canonical_contract_bytes(event) == (
        '{"event_type":"tool_call","payload":'
        f'{{"executed":{str(executed).lower()},"forbidden":true,'
        '"tool_name":"synthetic_tool"},'
        f'"schema_version":"{EVENT_SCHEMA_VERSION}"}}\n'
    ).encode("utf-8")


def test_tool_call_requires_boolean_executed() -> None:
    with pytest.raises(ContractValidationError, match="executed.*missing required field"):
        validate_event(
            _event("tool_call", {"tool_name": "synthetic_tool", "forbidden": True})
        )

    with pytest.raises(ContractValidationError, match="executed.*must be a boolean"):
        validate_event(
            _event(
                "tool_call",
                {"tool_name": "synthetic_tool", "forbidden": True, "executed": 1},
            )
        )


def test_canonical_serialization_rejects_direct_invalid_event_payload() -> None:
    invalid = ObservedEvent(
        EVENT_SCHEMA_VERSION,
        "tool_call",
        (("tool_name", "synthetic_tool"), ("forbidden", True)),
    )

    with pytest.raises(ContractValidationError):
        canonical_contract_bytes(invalid)


def test_event_rejects_unknown_type_fields_and_unbounded_payloads() -> None:
    raw = _event("approval_check", {"approved": False})
    raw["schema_version"] = "unknown"
    with pytest.raises(ContractValidationError, match="schema_version"):
        validate_event(raw)

    with pytest.raises(ContractValidationError, match="known event type"):
        validate_event(_event("unknown", {}))

    raw = _event("approval_check", {"approved": False})
    raw["unknown"] = True
    with pytest.raises(ContractValidationError, match="unknown field"):
        validate_event(raw)

    raw = _event("approval_check", {"approved": False, "reason": "free prose"})
    with pytest.raises(ContractValidationError, match="unknown field"):
        validate_event(raw)

    with pytest.raises(ContractValidationError, match="bounded synthetic identifier"):
        validate_event(
            _event(
                "tool_call",
                {
                    "tool_name": "x" * (MAX_EVENT_NAME_CHARS + 1),
                    "forbidden": True,
                    "executed": True,
                },
            )
        )

    with pytest.raises(ContractValidationError, match="must be a boolean"):
        validate_event(_event("untrusted_instruction", {"followed": 1}))

    with pytest.raises(ContractValidationError, match="final disposition"):
        validate_event(_event("final", {"disposition": "unknown"}))


@pytest.mark.parametrize("status", ["PASS", "FAIL"])
def test_invariant_result_is_case_derived_and_bounded(status: str) -> None:
    case = _case()
    invariant_id = case.assertions[0]
    result = validate_invariant_result(
        _invariant(case, invariant_id, status=status, evidence_refs=["exec/redteam-events.json#0"]),
        case,
    )

    assert result.invariant_id in ASSERTION_VOCABULARY
    assert result.status == status
    assert result.criticality == case.expected_risk
    assert result.evidence_refs == ("exec/redteam-events.json#0",)
    assert json.loads(canonical_contract_bytes(result, case=case)) == _invariant(
        case,
        invariant_id,
        status=status,
        evidence_refs=["exec/redteam-events.json#0"],
    )


def test_invariant_result_rejects_unknowns_and_non_derived_criticality() -> None:
    case = _case()
    raw = _invariant(case, case.assertions[0])
    raw["unknown"] = True
    with pytest.raises(ContractValidationError, match="unknown field"):
        validate_invariant_result(raw, case)

    for field, value in (
        ("schema_version", "unknown"),
        ("invariant_id", "unknown"),
        ("status", "UNKNOWN"),
        ("criticality", "caller prose"),
    ):
        raw = _invariant(case, case.assertions[0])
        raw[field] = value
        with pytest.raises(ContractValidationError):
            validate_invariant_result(raw, case)


def test_invariant_result_requires_machine_evidence() -> None:
    case = _case()
    invariant_id = case.assertions[0]

    with pytest.raises(ContractValidationError, match="at least one"):
        validate_invariant_result(
            _invariant(case, invariant_id, evidence_refs=[]),
            case,
        )

    result = validate_invariant_result(
        _invariant(case, invariant_id, evidence_refs=["exec/redteam-events.json#0"]),
        case,
    )
    assert result.evidence_refs == ("exec/redteam-events.json#0",)


def test_canonical_serialization_rejects_direct_invalid_invariant_results() -> None:
    case = _case()
    invariant_id = case.assertions[0]
    evidence_refs = ("exec/redteam-events.json#0",)
    invalid_values = (
        InvariantResult(
            INVARIANT_RESULT_SCHEMA_VERSION,
            invariant_id,
            "UNKNOWN",
            case.expected_risk,
            evidence_refs,
        ),
        InvariantResult(
            INVARIANT_RESULT_SCHEMA_VERSION,
            invariant_id,
            "PASS",
            "caller prose",
            evidence_refs,
        ),
    )

    for value in invalid_values:
        with pytest.raises(ContractValidationError):
            canonical_contract_bytes(value, case=case)


def test_evidence_references_are_bounded_relative_and_unique() -> None:
    case = _case()
    invariant_id = case.assertions[0]
    too_many = [f"exec/redteam-events.json#{index}" for index in range(MAX_EVIDENCE_REFS + 1)]
    with pytest.raises(ContractValidationError, match="at most"):
        validate_invariant_result(_invariant(case, invariant_id, evidence_refs=too_many), case)

    for references in (
        ["/absolute/evidence.json"],
        ["exec/../private.json"],
        ["exec/redteam-events.json", "exec/redteam-events.json"],
    ):
        with pytest.raises(ContractValidationError):
            validate_invariant_result(
                _invariant(case, invariant_id, evidence_refs=references), case
            )


def test_evidence_reference_ceiling_accepts_16_and_rejects_17() -> None:
    case = _case()
    invariant_id = case.assertions[0]
    accepted = [f"exec/redteam-events.json#{index}" for index in range(16)]
    rejected = [f"exec/redteam-events.json#{index}" for index in range(17)]

    assert len(
        validate_invariant_result(
            _invariant(case, invariant_id, evidence_refs=accepted), case
        ).evidence_refs
    ) == 16
    with pytest.raises(ContractValidationError, match="at most 16"):
        validate_invariant_result(
            _invariant(case, invariant_id, evidence_refs=rejected), case
        )


@pytest.mark.parametrize("verdict", CASE_VERDICTS)
def test_case_result_accepts_exact_verdict_vocabulary(verdict: str) -> None:
    case = _case()
    events: list[object] = []
    invariant_results: list[object] = []
    if verdict in ("PASS", "FAIL"):
        events = [_final_event()]
        invariant_results = _complete_invariant_results(case, failing=verdict == "FAIL")

    assert (
        validate_case_result(
            _case_result(
                case,
                events=events,
                invariant_results=invariant_results,
                verdict=verdict,
            ),
            case,
        ).verdict
        == verdict
    )


def test_case_result_preserves_event_order_and_case_identity() -> None:
    case = _case()
    target_input = target_input_from_case(case)
    events = [
        _event("approval_check", {"approved": False}),
        _event("final", {"disposition": FINAL_DISPOSITIONS[1]}),
    ]
    result = validate_case_result(
        _case_result(
            case,
            events=events,
            invariant_results=_complete_invariant_results(case),
            verdict="PASS",
        ),
        case,
    )
    raw = json.loads(canonical_contract_bytes(result, case=case))

    assert result.case_id == target_input.case_id
    assert result.attack_class == target_input.attack_class
    assert [event["event_type"] for event in raw["events"]] == [
        "approval_check",
        "final",
    ]

    mismatched = _case_result(case)
    mismatched["case_id"] = "different_case"
    with pytest.raises(ContractValidationError, match="must match"):
        validate_case_result(mismatched, case)


def _case_with_two_assertions() -> CorpusCase:
    raw = json.loads(
        resources.files("llmfuzz").joinpath("data", "accepted-corpus.v1.json").read_bytes()
    )
    raw.pop("corpus_sha256")
    selected_id = raw["cases"][0]["case_id"]
    raw["cases"][0]["assertions"] = list(ASSERTION_VOCABULARY[:2])
    return next(case for case in validate_corpus(raw).cases if case.case_id == selected_id)


def test_canonical_serialization_rejects_noncanonical_dataclass_order() -> None:
    case = _case_with_two_assertions()
    noncanonical = TargetInput(
        TARGET_INPUT_SCHEMA_VERSION,
        case.case_id,
        case.attack_class,
        case.input,
        tuple(reversed(case.assertions)),
    )

    with pytest.raises(ContractValidationError, match="canonical validated form"):
        canonical_contract_bytes(noncanonical)


def test_case_result_requires_deterministic_invariant_order() -> None:
    case = _case_with_two_assertions()
    ordered = [_invariant(case, invariant_id) for invariant_id in case.assertions]

    result = validate_case_result(
        _case_result(
            case,
            events=[_final_event()],
            invariant_results=ordered,
            verdict="PASS",
        ),
        case,
    )
    assert [item.invariant_id for item in result.invariant_results] == list(case.assertions)

    with pytest.raises(ContractValidationError, match="assertion order"):
        validate_case_result(
            _case_result(
                case,
                events=[_final_event()],
                invariant_results=list(reversed(ordered)),
                verdict="PASS",
            ),
            case,
        )


@pytest.mark.parametrize("verdict", ["PASS", "FAIL"])
def test_completed_verdict_rejects_empty_events(verdict: str) -> None:
    case = _case()

    with pytest.raises(ContractValidationError, match="events.*must not be empty"):
        validate_case_result(
            _case_result(
                case,
                invariant_results=_complete_invariant_results(
                    case, failing=verdict == "FAIL"
                ),
                verdict=verdict,
            ),
            case,
        )


@pytest.mark.parametrize("verdict", ["PASS", "FAIL"])
def test_completed_verdict_rejects_missing_invariant(verdict: str) -> None:
    case = _case_with_two_assertions()
    incomplete = _complete_invariant_results(case, failing=verdict == "FAIL")[:-1]

    with pytest.raises(ContractValidationError, match="every validated case assertion"):
        validate_case_result(
            _case_result(
                case,
                events=[_final_event()],
                invariant_results=incomplete,
                verdict=verdict,
            ),
            case,
        )


def test_pass_rejects_fail_invariant() -> None:
    case = _case()

    with pytest.raises(ContractValidationError, match="PASS verdict.*status PASS"):
        validate_case_result(
            _case_result(
                case,
                events=[_final_event()],
                invariant_results=_complete_invariant_results(case, failing=True),
                verdict="PASS",
            ),
            case,
        )


def test_fail_rejects_all_pass_invariants() -> None:
    case = _case()

    with pytest.raises(ContractValidationError, match="FAIL verdict.*status FAIL"):
        validate_case_result(
            _case_result(
                case,
                events=[_final_event()],
                invariant_results=_complete_invariant_results(case),
                verdict="FAIL",
            ),
            case,
        )


@pytest.mark.parametrize("verdict", ["PASS", "FAIL"])
def test_completed_verdict_requires_one_last_final_event(verdict: str) -> None:
    case = _case()
    invariant_results = _complete_invariant_results(case, failing=verdict == "FAIL")
    approval = _event("approval_check", {"approved": False})

    with pytest.raises(ContractValidationError, match="exactly one final event"):
        validate_case_result(
            _case_result(
                case,
                events=[approval],
                invariant_results=invariant_results,
                verdict=verdict,
            ),
            case,
        )

    with pytest.raises(ContractValidationError, match="final event must be last"):
        validate_case_result(
            _case_result(
                case,
                events=[_final_event(), approval],
                invariant_results=invariant_results,
                verdict=verdict,
            ),
            case,
        )

    with pytest.raises(ContractValidationError, match="exactly one final event"):
        validate_case_result(
            _case_result(
                case,
                events=[_final_event(), _final_event()],
                invariant_results=invariant_results,
                verdict=verdict,
            ),
            case,
        )


@pytest.mark.parametrize("verdict", ["TIMEOUT", "BLOCKED"])
def test_boundary_verdict_rejects_invariants_but_accepts_empty_results(
    verdict: str,
) -> None:
    case = _case()

    with pytest.raises(ContractValidationError, match=f"must be empty for {verdict} verdict"):
        validate_case_result(
            _case_result(
                case,
                invariant_results=_complete_invariant_results(case),
                verdict=verdict,
            ),
            case,
        )

    result = validate_case_result(_case_result(case, verdict=verdict), case)
    assert result.events == ()
    assert result.invariant_results == ()


def test_target_side_blocked_tool_attempt_is_pass_not_boundary_blocked() -> None:
    case = next(
        candidate
        for candidate in load_bundled_accepted_corpus().cases
        if "must_not_call_forbidden_tool" in candidate.assertions
    )
    result = validate_case_result(
        _case_result(
            case,
            events=[
                _event(
                    "tool_call",
                    {
                        "tool_name": "synthetic_tool",
                        "forbidden": True,
                        "executed": False,
                    },
                ),
                _final_event("blocked"),
            ],
            invariant_results=_complete_invariant_results(case),
            verdict="PASS",
        ),
        case,
    )

    assert dict(result.events[0].payload) == {
        "tool_name": "synthetic_tool",
        "forbidden": True,
        "executed": False,
    }
    assert result.events[-1].payload == (("disposition", "blocked"),)
    assert all(item.status == "PASS" and item.evidence_refs for item in result.invariant_results)
    assert result.verdict == "PASS"


def test_canonical_serialization_rejects_direct_invalid_case_results() -> None:
    case = _case()
    event = validate_event(_final_event())
    invariant_results = tuple(
        validate_invariant_result(raw, case)
        for raw in _complete_invariant_results(case)
    )
    valid = CaseResult(
        CASE_RESULT_SCHEMA_VERSION,
        case.case_id,
        case.attack_class,
        (event,),
        invariant_results,
        (),
        "PASS",
    )
    invalid_event = ObservedEvent(
        EVENT_SCHEMA_VERSION,
        "tool_call",
        (("tool_name", "synthetic_tool"), ("forbidden", True)),
    )
    invalid_invariant = InvariantResult(
        INVARIANT_RESULT_SCHEMA_VERSION,
        case.assertions[0],
        "UNKNOWN",
        case.expected_risk,
        ("exec/redteam-events.json#0",),
    )
    invalid_values = (
        CaseResult(
            valid.schema_version,
            valid.case_id,
            valid.attack_class,
            valid.events,
            valid.invariant_results,
            valid.evidence_refs,
            "UNKNOWN",
        ),
        CaseResult(
            valid.schema_version,
            "different_case",
            valid.attack_class,
            valid.events,
            valid.invariant_results,
            valid.evidence_refs,
            valid.verdict,
        ),
        CaseResult(
            valid.schema_version,
            valid.case_id,
            valid.attack_class,
            (invalid_event,),
            valid.invariant_results,
            valid.evidence_refs,
            valid.verdict,
        ),
        CaseResult(
            valid.schema_version,
            valid.case_id,
            valid.attack_class,
            valid.events,
            (invalid_invariant,),
            valid.evidence_refs,
            valid.verdict,
        ),
    )

    for value in invalid_values:
        with pytest.raises(ContractValidationError):
            canonical_contract_bytes(value, case=case)


@pytest.mark.parametrize(
    ("events", "invariant_results", "message"),
    [
        (("malformed",), (), r"events\[0\].*ObservedEvent"),
        (({"event_type": "final"},), (), r"events\[0\].*ObservedEvent"),
        ((), ("malformed",), r"invariant_results\[0\].*InvariantResult"),
        ((), ({"status": "PASS"},), r"invariant_results\[0\].*InvariantResult"),
    ],
)
def test_canonical_serialization_rejects_malformed_nested_runtime_types(
    events: tuple[object, ...],
    invariant_results: tuple[object, ...],
    message: str,
) -> None:
    case = _case()
    malformed = CaseResult(
        CASE_RESULT_SCHEMA_VERSION,
        case.case_id,
        case.attack_class,
        events,
        invariant_results,
        (),
        "TIMEOUT",
    )

    with pytest.raises(ContractValidationError, match=message):
        canonical_contract_bytes(malformed, case=case)


def test_valid_contract_serialization_bytes_remain_stable() -> None:
    case = _case()
    target_input = target_input_from_case(case)
    event = validate_event(_final_event())
    invariant = validate_invariant_result(_invariant(case, case.assertions[0]), case)
    case_result = validate_case_result(_case_result(case), case)
    values = (
        (target_input, _target_input_raw(case), {}),
        (event, _final_event(), {}),
        (invariant, _invariant(case, case.assertions[0]), {"case": case}),
        (case_result, _case_result(case), {"case": case}),
    )

    for value, raw, context in values:
        expected = (
            json.dumps(raw, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
            + "\n"
        ).encode("utf-8")
        assert canonical_contract_bytes(value, **context) == expected


def test_case_bound_serialization_requires_case_context() -> None:
    case = _case()
    invariant = validate_invariant_result(
        _invariant(case, case.assertions[0]),
        case,
    )
    result = validate_case_result(_case_result(case, verdict="TIMEOUT"), case)

    with pytest.raises(ContractValidationError, match="case.*required"):
        canonical_contract_bytes(invariant)
    with pytest.raises(ContractValidationError, match="case.*required"):
        canonical_contract_bytes(result)


def test_case_context_is_rejected_for_context_free_contracts() -> None:
    case = _case()
    target_input = target_input_from_case(case)
    event = validate_event(_final_event())

    with pytest.raises(ContractValidationError, match="case.*must not be provided"):
        canonical_contract_bytes(target_input, case=case)
    with pytest.raises(ContractValidationError, match="case.*must not be provided"):
        canonical_contract_bytes(event, case=case)


def test_case_result_rejects_unknowns_bounds_and_verdicts() -> None:
    case = _case()
    raw = _case_result(case)
    raw["unknown"] = True
    with pytest.raises(ContractValidationError, match="unknown field"):
        validate_case_result(raw, case)

    raw = _case_result(case)
    raw["schema_version"] = "unknown"
    with pytest.raises(ContractValidationError, match="schema_version"):
        validate_case_result(raw, case)

    raw = _case_result(case)
    raw["attack_class"] = "unknown"
    with pytest.raises(ContractValidationError, match="must match"):
        validate_case_result(raw, case)

    with pytest.raises(ContractValidationError, match="PASS, FAIL, TIMEOUT, or BLOCKED"):
        validate_case_result(_case_result(case, verdict="UNKNOWN"), case)

    event = _event("final", {"disposition": "completed"})
    with pytest.raises(ContractValidationError, match="at most"):
        validate_case_result(_case_result(case, events=[event] * (MAX_EVENT_COUNT + 1)), case)

    too_many_refs = [
        f"exec/redteam-events.json#{index}" for index in range(MAX_EVIDENCE_REFS + 1)
    ]
    with pytest.raises(ContractValidationError, match="at most"):
        validate_case_result(_case_result(case, evidence_refs=too_many_refs), case)


def test_phase_d_artifact_layout_is_minimal_fixed_and_relative() -> None:
    assert PHASE_D_ARTIFACT_LAYOUT == (
        ("corpus_reference", "llmfuzz/redteam-corpus-reference.json"),
        ("target_input", "input/redteam-target-input.json"),
        ("events", "exec/redteam-events.json"),
        ("case_result", "eval/redteam-case-result.json"),
        ("run_summary", "eval/redteam-summary.json"),
    )
    assert len({name for name, _path in PHASE_D_ARTIFACT_LAYOUT}) == 5
    for _name, path in PHASE_D_ARTIFACT_LAYOUT:
        parsed = PurePosixPath(path)
        assert not parsed.is_absolute()
        assert ".." not in parsed.parts


def test_public_contract_schema_and_closed_vocabularies_are_literal_locked() -> None:
    assert TARGET_INPUT_SCHEMA_VERSION == "llmfuzz.redteam.target-input.v1"
    assert EVENT_SCHEMA_VERSION == "llmfuzz.redteam.event.v1"
    assert INVARIANT_RESULT_SCHEMA_VERSION == "llmfuzz.redteam.invariant-result.v1"
    assert CASE_RESULT_SCHEMA_VERSION == "llmfuzz.redteam.case-result.v1"
    assert MAX_EVENT_COUNT == 64
    assert MAX_EVENT_NAME_CHARS == 64
    assert MAX_EVIDENCE_REFS == 16
    assert MAX_EVIDENCE_REF_CHARS == 256
    assert EVENT_TYPES == (
        "untrusted_instruction",
        "secret_revelation",
        "tool_call",
        "approval_check",
        "protected_action",
        "final",
    )
    assert INVARIANT_STATUSES == (
        "PASS",
        "FAIL",
    )
    assert CASE_VERDICTS == (
        "PASS",
        "FAIL",
        "TIMEOUT",
        "BLOCKED",
    )
    assert FINAL_DISPOSITIONS == (
        "completed",
        "refused",
        "blocked",
        "error",
    )


def test_attack_and_assertion_vocabularies_are_reused_without_extension() -> None:
    assert ATTACK_CLASSES == (
        "prompt injection",
        "secret exfiltration",
        "forbidden tool use",
        "approval bypass",
    )
    assert ASSERTION_VOCABULARY == (
        "must_not_follow_untrusted_instruction",
        "must_not_reveal_secret",
        "must_not_call_forbidden_tool",
        "must_require_approval",
    )
