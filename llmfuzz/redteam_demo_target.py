from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Tuple

from .redteam_contracts import (
    EVENT_SCHEMA_VERSION,
    MAX_EVENT_COUNT,
    ContractValidationError,
    ObservedEvent,
    TargetInput,
    canonical_contract_bytes,
    validate_event,
    validate_target_input,
)
from .redteam_corpus import ATTACK_CLASSES, MAX_CASE_ID_CHARS


VULNERABLE_TARGET_ID = "llmfuzz.redteam.demo-target.vulnerable.v1"
FIXED_TARGET_ID = "llmfuzz.redteam.demo-target.fixed.v1"
TARGET_OUTPUT_SCHEMA_VERSION = "llmfuzz.redteam.target-output.v1"

SYNTHETIC_FORBIDDEN_TOOL = "synthetic_forbidden_tool"
SYNTHETIC_PROTECTED_ACTION = "synthetic_protected_action"

# Maximum canonical target-input size derived from the locked D0 bounds.
MAX_TARGET_INPUT_BYTES = 49_465
MAX_TARGET_OUTPUT_BYTES = 32_768

_TARGET_IDS = (VULNERABLE_TARGET_ID, FIXED_TARGET_ID)
_TARGET_OUTPUT_FIELDS = ("schema_version", "target_id", "case_id", "events")
_CASE_ID_RE = re.compile(rf"^[a-z0-9._-]{{1,{MAX_CASE_ID_CHARS}}}$")


class DemoTargetValidationError(ValueError):
    pass


@dataclass(frozen=True)
class DemoTargetPolicy:
    target_id: str
    unsafe_actions_enabled: bool


@dataclass(frozen=True)
class TargetOutput:
    schema_version: str
    target_id: str
    case_id: str
    events: Tuple[ObservedEvent, ...]


VULNERABLE_POLICY = DemoTargetPolicy(VULNERABLE_TARGET_ID, True)
FIXED_POLICY = DemoTargetPolicy(FIXED_TARGET_ID, False)


def _fail(path: str, reason: str) -> None:
    raise DemoTargetValidationError(f"{path}: {reason}")


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


def _validated_target_input(value: object) -> TargetInput:
    if not isinstance(value, TargetInput):
        _fail("target_input", "must be a validated TargetInput")
    try:
        canonical_contract_bytes(value)
    except ContractValidationError:
        _fail("target_input", "must be a validated TargetInput")
    return value


def _validated_policy(value: object) -> DemoTargetPolicy:
    if (
        not isinstance(value, DemoTargetPolicy)
        or value not in (VULNERABLE_POLICY, FIXED_POLICY)
        or not isinstance(value.unsafe_actions_enabled, bool)
    ):
        _fail("policy", "must be a locked demo-target policy")
    return value


def _event(event_type: str, payload: dict[str, object]) -> ObservedEvent:
    return validate_event(
        {
            "schema_version": EVENT_SCHEMA_VERSION,
            "event_type": event_type,
            "payload": payload,
        }
    )


def execute_demo_target(
    target_input: TargetInput,
    policy: DemoTargetPolicy,
) -> Tuple[ObservedEvent, ...]:
    target_input = _validated_target_input(target_input)
    policy = _validated_policy(policy)
    unsafe = policy.unsafe_actions_enabled

    if target_input.attack_class == ATTACK_CLASSES[0]:
        events = (
            _event("untrusted_instruction", {"followed": unsafe}),
            _event("final", {"disposition": "completed"}),
        )
    elif target_input.attack_class == ATTACK_CLASSES[1]:
        events = (
            _event("secret_revelation", {"revealed": unsafe}),
            _event("final", {"disposition": "completed" if unsafe else "refused"}),
        )
    elif target_input.attack_class == ATTACK_CLASSES[2]:
        events = (
            _event(
                "tool_call",
                {
                    "tool_name": SYNTHETIC_FORBIDDEN_TOOL,
                    "forbidden": True,
                    "executed": unsafe,
                },
            ),
            _event("final", {"disposition": "completed" if unsafe else "blocked"}),
        )
    elif target_input.attack_class == ATTACK_CLASSES[3]:
        events = (
            _event("approval_check", {"approved": False}),
            _event(
                "protected_action",
                {
                    "action_name": SYNTHETIC_PROTECTED_ACTION,
                    "executed": unsafe,
                },
            ),
            _event("final", {"disposition": "completed" if unsafe else "blocked"}),
        )
    else:  # pragma: no cover - validated TargetInput makes this unreachable
        _fail("target_input.attack_class", "must be an authorized attack class")

    return events


def target_output_for(
    target_input: TargetInput,
    policy: DemoTargetPolicy,
) -> TargetOutput:
    target_input = _validated_target_input(target_input)
    policy = _validated_policy(policy)
    return validate_target_output(
        {
            "schema_version": TARGET_OUTPUT_SCHEMA_VERSION,
            "target_id": policy.target_id,
            "case_id": target_input.case_id,
            "events": [
                json.loads(canonical_contract_bytes(event))
                for event in execute_demo_target(target_input, policy)
            ],
        },
        expected_input=target_input,
    )


def validate_target_output(
    raw: object,
    *,
    expected_input: TargetInput | None = None,
) -> TargetOutput:
    value = _validate_keys(raw, _TARGET_OUTPUT_FIELDS, "target_output")
    if value["schema_version"] != TARGET_OUTPUT_SCHEMA_VERSION:
        _fail(
            "target_output.schema_version",
            f"must equal {TARGET_OUTPUT_SCHEMA_VERSION}",
        )
    target_id = value["target_id"]
    if not isinstance(target_id, str) or target_id not in _TARGET_IDS:
        _fail("target_output.target_id", "must be a locked demo-target identity")
    case_id = value["case_id"]
    if not isinstance(case_id, str) or not _CASE_ID_RE.fullmatch(case_id):
        _fail("target_output.case_id", "must be a bounded lowercase case identifier")
    if expected_input is not None:
        expected_input = _validated_target_input(expected_input)
        if case_id != expected_input.case_id:
            _fail("target_output.case_id", "must match the expected target input")

    events_raw = value["events"]
    if not isinstance(events_raw, list):
        _fail("target_output.events", "must be an array")
    if len(events_raw) > MAX_EVENT_COUNT:
        _fail("target_output.events", f"must contain at most {MAX_EVENT_COUNT} events")
    events: list[ObservedEvent] = []
    for index, event_raw in enumerate(events_raw):
        try:
            events.append(validate_event(event_raw))
        except ContractValidationError:
            _fail(f"target_output.events[{index}]", "must be a valid observed event")

    final_indexes = [
        index for index, event in enumerate(events) if event.event_type == "final"
    ]
    if len(final_indexes) != 1:
        _fail("target_output.events", "must contain exactly one final event")
    if final_indexes[0] != len(events) - 1:
        _fail("target_output.events", "final event must be last")
    return TargetOutput(
        TARGET_OUTPUT_SCHEMA_VERSION,
        target_id,
        case_id,
        tuple(events),
    )


def canonical_target_output_bytes(value: TargetOutput) -> bytes:
    try:
        if not isinstance(value, TargetOutput):
            _fail("target_output", "must be a validated TargetOutput")
        for index, event in enumerate(value.events):
            if not isinstance(event, ObservedEvent):
                _fail(
                    f"target_output.events[{index}]",
                    "must be an ObservedEvent",
                )
        raw = {
            "schema_version": value.schema_version,
            "target_id": value.target_id,
            "case_id": value.case_id,
            "events": [
                json.loads(canonical_contract_bytes(event)) for event in value.events
            ],
        }
        normalized = validate_target_output(raw)
        if normalized != value:
            _fail("target_output", "must already be in canonical validated form")
        text = json.dumps(
            raw,
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        )
    except DemoTargetValidationError:
        raise
    except (ContractValidationError, TypeError, ValueError):
        _fail("target_output", "contains invalid contract values")
    data = text.encode("utf-8") + b"\n"
    if len(data) > MAX_TARGET_OUTPUT_BYTES:
        _fail("target_output", f"must be at most {MAX_TARGET_OUTPUT_BYTES} bytes")
    return data


def _reject_json_constant(_value: str) -> None:
    raise ValueError("invalid JSON constant")


def _load_json_document(data: object, *, path: str, maximum: int) -> object:
    if not isinstance(data, bytes):
        _fail(path, "must be bytes")
    if not data or len(data) > maximum:
        _fail(path, f"must contain 1-{maximum} bytes")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        _fail(path, "must contain valid UTF-8")
    try:
        return json.loads(
            text,
            parse_constant=_reject_json_constant,
        )
    except (json.JSONDecodeError, RecursionError, ValueError):
        _fail(path, "must contain exactly one valid JSON document")


def load_target_input_bytes(data: bytes) -> TargetInput:
    raw = _load_json_document(
        data,
        path="target_input",
        maximum=MAX_TARGET_INPUT_BYTES,
    )
    try:
        target_input = validate_target_input(raw)
        canonical = canonical_contract_bytes(target_input)
    except ContractValidationError:
        _fail("target_input", "must satisfy the locked target-input contract")
    if data != canonical:
        _fail("target_input", "must use canonical JSON with one trailing newline")
    return target_input


def load_target_output_bytes(
    data: bytes,
    *,
    expected_input: TargetInput | None = None,
) -> TargetOutput:
    raw = _load_json_document(
        data,
        path="target_output",
        maximum=MAX_TARGET_OUTPUT_BYTES,
    )
    target_output = validate_target_output(raw, expected_input=expected_input)
    if data != canonical_target_output_bytes(target_output):
        _fail("target_output", "must use canonical JSON with one trailing newline")
    return target_output
