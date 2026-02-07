from __future__ import annotations

import json
from dataclasses import dataclass, fields, is_dataclass
from enum import Enum
from typing import Any, Optional


class FailureVerdict(str, Enum):
    PASS = "PASS"
    FAIL_INPUT_INVALID = "FAIL_INPUT_INVALID"
    FAIL_MISSING_OUTPUT = "FAIL_MISSING_OUTPUT"
    FAIL_SCHEMA_INVALID = "FAIL_SCHEMA_INVALID"
    FAIL_OUTPUT_MISMATCH = "FAIL_OUTPUT_MISMATCH"
    FAIL_EXCEPTION = "FAIL_EXCEPTION"
    BLOCKED_POLICY = "BLOCKED_POLICY"
    TIMEOUT = "TIMEOUT"
    NONDETERMINISM = "NONDETERMINISM"


@dataclass(frozen=True)
class InputRef:
    path: str
    sha256: str


@dataclass(frozen=True)
class SpecRef:
    path: str
    sha256: str


@dataclass(frozen=True)
class MutationRef:
    path: str
    sha256: str


@dataclass(frozen=True)
class OutputRef:
    path: str
    sha256: str


@dataclass(frozen=True)
class ExecutionInfo:
    exit_code: int
    elapsed_ms: int
    stderr_tail: Optional[str] = None


@dataclass(frozen=True)
class Timestamps:
    started_utc: str
    finished_utc: str


def _to_json_obj(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value):
        result: dict[str, Any] = {}
        for field in fields(value):
            item = getattr(value, field.name)
            if item is None:
                continue
            result[field.name] = _to_json_obj(item)
        return result
    if isinstance(value, list):
        return [_to_json_obj(item) for item in value]
    return value


@dataclass(frozen=True)
class FailureRecord:
    schema_version: str
    run_id: str
    campaign_id: str
    artifact_id: str
    input: InputRef
    spec_ref: SpecRef
    mutation_ref: MutationRef
    execution: ExecutionInfo
    observed_outputs: list[OutputRef]
    verdict: FailureVerdict
    reason: str
    timestamps: Timestamps

    def to_dict(self) -> dict[str, Any]:
        return _to_json_obj(self)

    def to_json(self, **kwargs: Any) -> str:
        return json.dumps(self.to_dict(), **kwargs)
