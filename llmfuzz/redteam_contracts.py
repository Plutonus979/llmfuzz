from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Tuple

from .redteam_corpus import (
    ASSERTION_VOCABULARY,
    ATTACK_CLASSES,
    CASE_SCHEMA_VERSION,
    EXPECTED_RISK,
    MAX_CASE_ID_CHARS,
    MAX_INPUT_CHARS,
    CorpusCase,
)


TARGET_INPUT_SCHEMA_VERSION = "llmfuzz.redteam.target-input.v1"
EVENT_SCHEMA_VERSION = "llmfuzz.redteam.event.v1"
INVARIANT_RESULT_SCHEMA_VERSION = "llmfuzz.redteam.invariant-result.v1"
CASE_RESULT_SCHEMA_VERSION = "llmfuzz.redteam.case-result.v1"

EVENT_TYPES = (
    "untrusted_instruction",
    "secret_revelation",
    "tool_call",
    "approval_check",
    "protected_action",
    "final",
)
INVARIANT_STATUSES = ("PASS", "FAIL")
CASE_VERDICTS = ("PASS", "FAIL", "TIMEOUT", "BLOCKED")
FINAL_DISPOSITIONS = ("completed", "refused", "blocked", "error")

MAX_EVENT_COUNT = 64
MAX_EVENT_NAME_CHARS = 64
MAX_EVIDENCE_REFS = 16
MAX_EVIDENCE_REF_CHARS = 256

PHASE_D_ARTIFACT_LAYOUT = (
    ("corpus_reference", "llmfuzz/redteam-corpus-reference.json"),
    ("target_input", "input/redteam-target-input.json"),
    ("events", "exec/redteam-events.json"),
    ("case_result", "eval/redteam-case-result.json"),
    ("run_summary", "eval/redteam-summary.json"),
)

_TARGET_INPUT_FIELDS = ("schema_version", "case_id", "attack_class", "input", "assertions")
_EVENT_FIELDS = ("schema_version", "event_type", "payload")
_INVARIANT_RESULT_FIELDS = (
    "schema_version",
    "invariant_id",
    "status",
    "criticality",
    "evidence_refs",
)
_CASE_RESULT_FIELDS = (
    "schema_version",
    "case_id",
    "attack_class",
    "events",
    "invariant_results",
    "evidence_refs",
    "verdict",
)
_EVENT_PAYLOAD_FIELDS = {
    "untrusted_instruction": ("followed",),
    "secret_revelation": ("revealed",),
    "tool_call": ("tool_name", "forbidden", "executed"),
    "approval_check": ("approved",),
    "protected_action": ("action_name", "executed"),
    "final": ("disposition",),
}
_ASSERTION_ORDER = {value: index for index, value in enumerate(ASSERTION_VOCABULARY)}
_CASE_ID_RE = re.compile(rf"^[a-z0-9._-]{{1,{MAX_CASE_ID_CHARS}}}$")
_EVENT_NAME_RE = re.compile(rf"^[a-z][a-z0-9_-]{{0,{MAX_EVENT_NAME_CHARS - 1}}}$")
_EVIDENCE_REF_RE = re.compile(r"^[a-z0-9][a-z0-9._/-]*(?:#[0-9]{1,4})?$")


class ContractValidationError(ValueError):
    pass


@dataclass(frozen=True)
class TargetInput:
    schema_version: str
    case_id: str
    attack_class: str
    input: str
    assertions: Tuple[str, ...]


@dataclass(frozen=True)
class ObservedEvent:
    schema_version: str
    event_type: str
    payload: Tuple[Tuple[str, str | bool], ...]


@dataclass(frozen=True)
class InvariantResult:
    schema_version: str
    invariant_id: str
    status: str
    criticality: str
    evidence_refs: Tuple[str, ...]


@dataclass(frozen=True)
class CaseResult:
    schema_version: str
    case_id: str
    attack_class: str
    events: Tuple[ObservedEvent, ...]
    invariant_results: Tuple[InvariantResult, ...]
    evidence_refs: Tuple[str, ...]
    verdict: str


def _fail(path: str, reason: str) -> None:
    raise ContractValidationError(f"{path}: {reason}")


def _validate_keys(value: object, fields: Tuple[str, ...], path: str) -> dict[str, object]:
    if not isinstance(value, dict):
        _fail(path, "must be an object")
    for key in value:
        if not isinstance(key, str):
            _fail(path, "keys must be strings")
    for field in fields:
        if field not in value:
            _fail(f"{path}.{field}", "missing required field")
    allowed = set(fields)
    for key in sorted(value):
        if key not in allowed:
            _fail(f"{path}.{key}", "unknown field")
    return value


def _bounded_string(value: object, path: str, maximum: int) -> str:
    if not isinstance(value, str):
        _fail(path, "must be a string")
    if not value.strip():
        _fail(path, "must not be empty or whitespace only")
    if len(value) > maximum:
        _fail(path, f"must be at most {maximum} characters")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        _fail(path, "must contain valid UTF-8 text")
    return value


def _case_id(value: object, path: str) -> str:
    if not isinstance(value, str) or not _CASE_ID_RE.fullmatch(value):
        _fail(path, "must be a bounded lowercase case identifier")
    return value


def _validated_case(case: object) -> CorpusCase:
    if not isinstance(case, CorpusCase) or case.schema_version != CASE_SCHEMA_VERSION:
        _fail("case", "must be a validated CorpusCase")
    _case_id(case.case_id, "case.case_id")
    if case.attack_class not in ATTACK_CLASSES:
        _fail("case.attack_class", "must be an authorized attack class")
    _bounded_string(case.input, "case.input", MAX_INPUT_CHARS)
    if case.expected_risk != EXPECTED_RISK:
        _fail("case.expected_risk", f"must equal {EXPECTED_RISK}")
    if not isinstance(case.assertions, tuple):
        _fail("case.assertions", "must be a validated assertion tuple")
    assertions = _assertions(list(case.assertions), "case.assertions")
    if assertions != case.assertions:
        _fail("case.assertions", "must use canonical assertion order")
    return case


def _assertions(value: object, path: str) -> Tuple[str, ...]:
    if not isinstance(value, list):
        _fail(path, "must be an array")
    if not value or len(value) > len(ASSERTION_VOCABULARY):
        _fail(path, f"must contain 1-{len(ASSERTION_VOCABULARY)} assertions")
    assertions: list[str] = []
    for assertion in value:
        if not isinstance(assertion, str) or assertion not in ASSERTION_VOCABULARY:
            _fail(path, "contains an unknown assertion")
        if assertion in assertions:
            _fail(path, "must not contain duplicates")
        assertions.append(assertion)
    return tuple(sorted(assertions, key=_ASSERTION_ORDER.__getitem__))


def _evidence_refs(value: object, path: str) -> Tuple[str, ...]:
    if not isinstance(value, list):
        _fail(path, "must be an array")
    if len(value) > MAX_EVIDENCE_REFS:
        _fail(path, f"must contain at most {MAX_EVIDENCE_REFS} references")
    references: list[str] = []
    for reference in value:
        reference = _bounded_string(reference, path, MAX_EVIDENCE_REF_CHARS)
        relative_path = reference.split("#", 1)[0]
        if not _EVIDENCE_REF_RE.fullmatch(reference) or any(
            part in ("", ".", "..") for part in relative_path.split("/")
        ):
            _fail(path, "must contain only bounded relative artifact references")
        if reference in references:
            _fail(path, "must not contain duplicates")
        references.append(reference)
    return tuple(references)


def validate_target_input(raw: object) -> TargetInput:
    value = _validate_keys(raw, _TARGET_INPUT_FIELDS, "target_input")
    if value["schema_version"] != TARGET_INPUT_SCHEMA_VERSION:
        _fail("target_input.schema_version", f"must equal {TARGET_INPUT_SCHEMA_VERSION}")
    case_id = _case_id(value["case_id"], "target_input.case_id")
    attack_class = value["attack_class"]
    if attack_class not in ATTACK_CLASSES:
        _fail("target_input.attack_class", "must be an authorized attack class")
    target_text = _bounded_string(value["input"], "target_input.input", MAX_INPUT_CHARS)
    assertions = _assertions(value["assertions"], "target_input.assertions")
    return TargetInput(
        TARGET_INPUT_SCHEMA_VERSION,
        case_id,
        attack_class,
        target_text,
        assertions,
    )


def target_input_from_case(case: CorpusCase) -> TargetInput:
    case = _validated_case(case)
    return validate_target_input(
        {
            "schema_version": TARGET_INPUT_SCHEMA_VERSION,
            "case_id": case.case_id,
            "attack_class": case.attack_class,
            "input": case.input,
            "assertions": list(case.assertions),
        }
    )


def validate_event(raw: object) -> ObservedEvent:
    value = _validate_keys(raw, _EVENT_FIELDS, "event")
    if value["schema_version"] != EVENT_SCHEMA_VERSION:
        _fail("event.schema_version", f"must equal {EVENT_SCHEMA_VERSION}")
    event_type = value["event_type"]
    if event_type not in EVENT_TYPES:
        _fail("event.event_type", "must be a known event type")
    fields = _EVENT_PAYLOAD_FIELDS[event_type]
    payload = _validate_keys(value["payload"], fields, "event.payload")

    if event_type == "untrusted_instruction":
        _require_bool(payload["followed"], "event.payload.followed")
    elif event_type == "secret_revelation":
        _require_bool(payload["revealed"], "event.payload.revealed")
    elif event_type == "tool_call":
        _event_name(payload["tool_name"], "event.payload.tool_name")
        _require_bool(payload["forbidden"], "event.payload.forbidden")
        _require_bool(payload["executed"], "event.payload.executed")
    elif event_type == "approval_check":
        _require_bool(payload["approved"], "event.payload.approved")
    elif event_type == "protected_action":
        _event_name(payload["action_name"], "event.payload.action_name")
        _require_bool(payload["executed"], "event.payload.executed")
    elif payload["disposition"] not in FINAL_DISPOSITIONS:
        _fail("event.payload.disposition", "must be a known final disposition")

    return ObservedEvent(
        EVENT_SCHEMA_VERSION,
        event_type,
        tuple((field, payload[field]) for field in fields),
    )


def _require_bool(value: object, path: str) -> bool:
    if not isinstance(value, bool):
        _fail(path, "must be a boolean")
    return value


def _event_name(value: object, path: str) -> str:
    if not isinstance(value, str) or not _EVENT_NAME_RE.fullmatch(value):
        _fail(path, "must be a bounded synthetic identifier")
    return value


def validate_invariant_result(raw: object, case: CorpusCase) -> InvariantResult:
    case = _validated_case(case)
    value = _validate_keys(raw, _INVARIANT_RESULT_FIELDS, "invariant_result")
    if value["schema_version"] != INVARIANT_RESULT_SCHEMA_VERSION:
        _fail(
            "invariant_result.schema_version",
            f"must equal {INVARIANT_RESULT_SCHEMA_VERSION}",
        )
    invariant_id = value["invariant_id"]
    if invariant_id not in ASSERTION_VOCABULARY or invariant_id not in case.assertions:
        _fail("invariant_result.invariant_id", "must be an assertion from the validated case")
    status = value["status"]
    if status not in INVARIANT_STATUSES:
        _fail("invariant_result.status", "must be PASS or FAIL")
    if value["criticality"] != case.expected_risk:
        _fail("invariant_result.criticality", "must be derived from the validated case risk")
    evidence_refs = _evidence_refs(value["evidence_refs"], "invariant_result.evidence_refs")
    if not evidence_refs:
        _fail("invariant_result.evidence_refs", "must contain at least one reference")
    return InvariantResult(
        INVARIANT_RESULT_SCHEMA_VERSION,
        invariant_id,
        status,
        case.expected_risk,
        evidence_refs,
    )


def validate_case_result(raw: object, case: CorpusCase) -> CaseResult:
    case = _validated_case(case)
    value = _validate_keys(raw, _CASE_RESULT_FIELDS, "case_result")
    if value["schema_version"] != CASE_RESULT_SCHEMA_VERSION:
        _fail("case_result.schema_version", f"must equal {CASE_RESULT_SCHEMA_VERSION}")
    case_id = _case_id(value["case_id"], "case_result.case_id")
    if case_id != case.case_id:
        _fail("case_result.case_id", "must match the validated case")
    attack_class = value["attack_class"]
    if attack_class != case.attack_class:
        _fail("case_result.attack_class", "must match the validated case")

    events_raw = value["events"]
    if not isinstance(events_raw, list):
        _fail("case_result.events", "must be an array")
    if len(events_raw) > MAX_EVENT_COUNT:
        _fail("case_result.events", f"must contain at most {MAX_EVENT_COUNT} events")
    events = tuple(validate_event(event) for event in events_raw)

    results_raw = value["invariant_results"]
    if not isinstance(results_raw, list):
        _fail("case_result.invariant_results", "must be an array")
    if len(results_raw) > len(case.assertions):
        _fail("case_result.invariant_results", "cannot exceed the validated case assertions")
    invariant_results = tuple(validate_invariant_result(result, case) for result in results_raw)
    invariant_ids = [result.invariant_id for result in invariant_results]
    if len(invariant_ids) != len(set(invariant_ids)):
        _fail("case_result.invariant_results", "must not contain duplicate invariant IDs")
    expected_order = [assertion for assertion in case.assertions if assertion in invariant_ids]
    if invariant_ids != expected_order:
        _fail("case_result.invariant_results", "must follow validated assertion order")

    evidence_refs = _evidence_refs(value["evidence_refs"], "case_result.evidence_refs")
    verdict = value["verdict"]
    if verdict not in CASE_VERDICTS:
        _fail("case_result.verdict", "must be PASS, FAIL, TIMEOUT, or BLOCKED")

    if verdict in ("PASS", "FAIL"):
        if not events:
            _fail("case_result.events", "must not be empty for PASS or FAIL")
        final_indexes = [
            index for index, event in enumerate(events) if event.event_type == "final"
        ]
        if len(final_indexes) != 1:
            _fail(
                "case_result.events",
                "must contain exactly one final event for PASS or FAIL",
            )
        if final_indexes[0] != len(events) - 1:
            _fail("case_result.events", "final event must be last for PASS or FAIL")
        if invariant_ids != list(case.assertions):
            _fail(
                "case_result.invariant_results",
                "must contain exactly one result for every validated case assertion",
            )
        if verdict == "PASS" and any(
            result.status != "PASS" for result in invariant_results
        ):
            _fail(
                "case_result.invariant_results",
                "PASS verdict requires every invariant status PASS",
            )
        if verdict == "FAIL" and not any(
            result.status == "FAIL" for result in invariant_results
        ):
            _fail(
                "case_result.invariant_results",
                "FAIL verdict requires at least one invariant status FAIL",
            )
    elif invariant_results:
        _fail(
            "case_result.invariant_results",
            f"must be empty for {verdict} verdict",
        )

    return CaseResult(
        CASE_RESULT_SCHEMA_VERSION,
        case_id,
        attack_class,
        events,
        invariant_results,
        evidence_refs,
        verdict,
    )


def canonical_contract_bytes(
    value: TargetInput | ObservedEvent | InvariantResult | CaseResult,
    *,
    case: CorpusCase | None = None,
) -> bytes:
    try:
        if isinstance(value, TargetInput):
            if case is not None:
                _fail("case", "must not be provided for TargetInput serialization")
            normalized = validate_target_input(_target_input_object(value))
            if normalized != value:
                _fail("contract", "must already be in canonical validated form")
            raw = _target_input_object(normalized)
        elif isinstance(value, ObservedEvent):
            if case is not None:
                _fail("case", "must not be provided for ObservedEvent serialization")
            normalized = validate_event(_event_object(value))
            if normalized != value:
                _fail("contract", "must already be in canonical validated form")
            raw = _event_object(normalized)
        elif isinstance(value, InvariantResult):
            if case is None:
                _fail("case", "is required for InvariantResult serialization")
            normalized = validate_invariant_result(_invariant_result_object(value), case)
            if normalized != value:
                _fail("contract", "must already be in canonical validated form")
            raw = _invariant_result_object(normalized)
        elif isinstance(value, CaseResult):
            if case is None:
                _fail("case", "is required for CaseResult serialization")
            normalized = validate_case_result(_case_result_object(value), case)
            if normalized != value:
                _fail("contract", "must already be in canonical validated form")
            raw = _case_result_object(normalized)
        else:
            _fail("contract", "must be a validated D0 contract")
        text = json.dumps(
            raw,
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        )
    except ContractValidationError:
        raise
    except (TypeError, ValueError):
        _fail("contract", "contains invalid dataclass field values")
    return text.encode("utf-8") + b"\n"


def _target_input_object(value: TargetInput) -> dict[str, object]:
    return {
        "schema_version": value.schema_version,
        "case_id": value.case_id,
        "attack_class": value.attack_class,
        "input": value.input,
        "assertions": list(value.assertions),
    }


def _event_object(value: ObservedEvent) -> dict[str, object]:
    return {
        "schema_version": value.schema_version,
        "event_type": value.event_type,
        "payload": dict(value.payload),
    }


def _invariant_result_object(value: InvariantResult) -> dict[str, object]:
    return {
        "schema_version": value.schema_version,
        "invariant_id": value.invariant_id,
        "status": value.status,
        "criticality": value.criticality,
        "evidence_refs": list(value.evidence_refs),
    }


def _case_result_object(value: CaseResult) -> dict[str, object]:
    for index, event in enumerate(value.events):
        if not isinstance(event, ObservedEvent):
            _fail(f"case_result.events[{index}]", "must be an ObservedEvent")
    for index, result in enumerate(value.invariant_results):
        if not isinstance(result, InvariantResult):
            _fail(
                f"case_result.invariant_results[{index}]",
                "must be an InvariantResult",
            )
    return {
        "schema_version": value.schema_version,
        "case_id": value.case_id,
        "attack_class": value.attack_class,
        "events": [_event_object(event) for event in value.events],
        "invariant_results": [
            _invariant_result_object(result) for result in value.invariant_results
        ],
        "evidence_refs": list(value.evidence_refs),
        "verdict": value.verdict,
    }
