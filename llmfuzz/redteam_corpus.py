from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, Tuple

from .io import atomic_write_bytes


CORPUS_SCHEMA_VERSION = "llmfuzz.redteam.corpus.v1"
CASE_SCHEMA_VERSION = "llmfuzz.redteam.case.v1"

ATTACK_CLASSES = (
    "prompt injection",
    "secret exfiltration",
    "forbidden tool use",
    "approval bypass",
)
ASSERTION_VOCABULARY = (
    "must_not_follow_untrusted_instruction",
    "must_not_reveal_secret",
    "must_not_call_forbidden_tool",
    "must_require_approval",
)

MIN_CASE_COUNT = 12
MAX_CASE_COUNT = 20
MAX_CASE_ID_CHARS = 64
MAX_INPUT_CHARS = 8192
MAX_RATIONALE_CHARS = 1024
MAX_MODEL_CHARS = 128
MAX_RESPONSE_ID_CHARS = 256
EXPECTED_RISK = "critical"

_CASE_ID_RE = re.compile(rf"^[a-z0-9._-]{{1,{MAX_CASE_ID_CHARS}}}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_UTC_SECONDS_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
)
_PAYLOAD_FIELDS = ("schema_version", "generation_metadata", "cases")
_PERSISTED_FIELDS = (*_PAYLOAD_FIELDS, "corpus_sha256")
_METADATA_FIELDS = (
    "model",
    "openai_response_id",
    "prompt_sha256",
    "output_schema_version",
    "generation_timestamp",
    "requested_case_count",
    "generated_case_count",
    "token_usage",
)
_CASE_FIELDS = (
    "schema_version",
    "case_id",
    "attack_class",
    "input",
    "expected_risk",
    "rationale",
    "assertions",
)
_TOKEN_USAGE_FIELDS = ("input_tokens", "output_tokens", "total_tokens")
_ASSERTION_ORDER = {value: index for index, value in enumerate(ASSERTION_VOCABULARY)}


class CorpusValidationError(ValueError):
    pass


@dataclass(frozen=True)
class TokenUsage:
    input_tokens: int
    output_tokens: int
    total_tokens: int


@dataclass(frozen=True)
class GenerationMetadata:
    model: str
    openai_response_id: str
    prompt_sha256: str
    output_schema_version: str
    generation_timestamp: str
    requested_case_count: int
    generated_case_count: int
    token_usage: TokenUsage | None


@dataclass(frozen=True)
class CorpusCase:
    schema_version: str
    case_id: str
    attack_class: str
    input: str
    expected_risk: str
    rationale: str
    assertions: Tuple[str, ...]


@dataclass(frozen=True)
class Corpus:
    schema_version: str
    generation_metadata: GenerationMetadata
    cases: Tuple[CorpusCase, ...]
    corpus_sha256: str


def _fail(path: str, reason: str) -> None:
    raise CorpusValidationError(f"{path}: {reason}")


def _field_path(prefix: str, key: str) -> str:
    return f"{prefix}.{key}" if prefix else key


def _validate_keys(
    value: object,
    allowed: Tuple[str, ...],
    required: Tuple[str, ...],
    path: str,
) -> Dict[str, object]:
    if not isinstance(value, dict):
        _fail(path, "must be an object")
    for key in value:
        if not isinstance(key, str):
            _fail(path, "keys must be strings")
    for key in required:
        if key not in value:
            _fail(_field_path(path, key), "missing required field")
    allowed_set = set(allowed)
    for key in sorted(value):
        if key not in allowed_set:
            _fail(_field_path(path, key), "unknown field")
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


def _bounded_int(value: object, path: str, minimum: int, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        _fail(path, "must be an integer")
    if value < minimum or value > maximum:
        _fail(path, f"must be between {minimum} and {maximum}")
    return value


def _nonnegative_int(value: object, path: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        _fail(path, "must be an integer")
    if value < 0:
        _fail(path, "must be greater than or equal to 0")
    return value


def _validate_token_usage(value: object, path: str) -> TokenUsage | None:
    if value is None:
        return None
    raw = _validate_keys(value, _TOKEN_USAGE_FIELDS, _TOKEN_USAGE_FIELDS, path)
    input_tokens = _nonnegative_int(raw["input_tokens"], f"{path}.input_tokens")
    output_tokens = _nonnegative_int(raw["output_tokens"], f"{path}.output_tokens")
    total_tokens = _nonnegative_int(raw["total_tokens"], f"{path}.total_tokens")
    if total_tokens != input_tokens + output_tokens:
        _fail(f"{path}.total_tokens", "must equal input_tokens + output_tokens")
    return TokenUsage(input_tokens, output_tokens, total_tokens)


def _validate_metadata(value: object) -> GenerationMetadata:
    required = tuple(field for field in _METADATA_FIELDS if field != "token_usage")
    raw = _validate_keys(value, _METADATA_FIELDS, required, "corpus.generation_metadata")
    prefix = "corpus.generation_metadata"

    model = _bounded_string(raw["model"], f"{prefix}.model", MAX_MODEL_CHARS)
    response_id = _bounded_string(
        raw["openai_response_id"],
        f"{prefix}.openai_response_id",
        MAX_RESPONSE_ID_CHARS,
    )
    prompt_sha256 = raw["prompt_sha256"]
    if not isinstance(prompt_sha256, str) or not _SHA256_RE.fullmatch(prompt_sha256):
        _fail(f"{prefix}.prompt_sha256", "must be 64 lowercase hexadecimal characters")

    output_schema_version = raw["output_schema_version"]
    if output_schema_version != CORPUS_SCHEMA_VERSION:
        _fail(f"{prefix}.output_schema_version", f"must equal {CORPUS_SCHEMA_VERSION}")

    timestamp = raw["generation_timestamp"]
    if not isinstance(timestamp, str) or not _UTC_SECONDS_RE.fullmatch(timestamp):
        _fail(f"{prefix}.generation_timestamp", "must be a UTC timestamp with second precision")
    try:
        datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        _fail(f"{prefix}.generation_timestamp", "must be a valid UTC timestamp")

    requested = _bounded_int(
        raw["requested_case_count"],
        f"{prefix}.requested_case_count",
        MIN_CASE_COUNT,
        MAX_CASE_COUNT,
    )
    generated = _bounded_int(
        raw["generated_case_count"],
        f"{prefix}.generated_case_count",
        MIN_CASE_COUNT,
        MAX_CASE_COUNT,
    )
    if requested != generated:
        _fail(f"{prefix}.requested_case_count", "must equal generated_case_count")

    token_usage = _validate_token_usage(raw.get("token_usage"), f"{prefix}.token_usage")
    return GenerationMetadata(
        model=model,
        openai_response_id=response_id,
        prompt_sha256=prompt_sha256,
        output_schema_version=output_schema_version,
        generation_timestamp=timestamp,
        requested_case_count=requested,
        generated_case_count=generated,
        token_usage=token_usage,
    )


def _validate_case(value: object, index: int) -> CorpusCase:
    path = f"corpus.cases[{index}]"
    raw = _validate_keys(value, _CASE_FIELDS, _CASE_FIELDS, path)

    schema_version = raw["schema_version"]
    if schema_version != CASE_SCHEMA_VERSION:
        _fail(f"{path}.schema_version", f"must equal {CASE_SCHEMA_VERSION}")

    case_id = raw["case_id"]
    if not isinstance(case_id, str):
        _fail(f"{path}.case_id", "must be a string")
    if not _CASE_ID_RE.fullmatch(case_id):
        _fail(
            f"{path}.case_id",
            f"must be 1-{MAX_CASE_ID_CHARS} lowercase ASCII letters, digits, period, underscore, or hyphen",
        )

    attack_class = raw["attack_class"]
    if attack_class not in ATTACK_CLASSES:
        _fail(f"{path}.attack_class", "must be one of the four authorized attack classes")

    case_input = _bounded_string(raw["input"], f"{path}.input", MAX_INPUT_CHARS)
    rationale = _bounded_string(raw["rationale"], f"{path}.rationale", MAX_RATIONALE_CHARS)

    expected_risk = raw["expected_risk"]
    if expected_risk != EXPECTED_RISK:
        _fail(f"{path}.expected_risk", f"must equal {EXPECTED_RISK}")

    assertions_raw = raw["assertions"]
    if not isinstance(assertions_raw, list):
        _fail(f"{path}.assertions", "must be an array")
    if not assertions_raw:
        _fail(f"{path}.assertions", "must not be empty")
    if len(assertions_raw) > len(ASSERTION_VOCABULARY):
        _fail(f"{path}.assertions", f"must contain at most {len(ASSERTION_VOCABULARY)} values")
    assertions: list[str] = []
    for assertion in assertions_raw:
        if not isinstance(assertion, str) or assertion not in ASSERTION_VOCABULARY:
            _fail(f"{path}.assertions", "contains an unknown assertion")
        if assertion in assertions:
            _fail(f"{path}.assertions", "must not contain duplicates")
        assertions.append(assertion)

    return CorpusCase(
        schema_version=schema_version,
        case_id=case_id,
        attack_class=attack_class,
        input=case_input,
        expected_risk=expected_risk,
        rationale=rationale,
        assertions=tuple(sorted(assertions, key=_ASSERTION_ORDER.__getitem__)),
    )


def _token_usage_object(token_usage: TokenUsage | None) -> dict[str, int] | None:
    if token_usage is None:
        return None
    return {
        "input_tokens": token_usage.input_tokens,
        "output_tokens": token_usage.output_tokens,
        "total_tokens": token_usage.total_tokens,
    }


def _payload_object(corpus: Corpus) -> dict[str, object]:
    metadata = corpus.generation_metadata
    return {
        "schema_version": corpus.schema_version,
        "generation_metadata": {
            "model": metadata.model,
            "openai_response_id": metadata.openai_response_id,
            "prompt_sha256": metadata.prompt_sha256,
            "output_schema_version": metadata.output_schema_version,
            "generation_timestamp": metadata.generation_timestamp,
            "requested_case_count": metadata.requested_case_count,
            "generated_case_count": metadata.generated_case_count,
            "token_usage": _token_usage_object(metadata.token_usage),
        },
        "cases": [
            {
                "schema_version": case.schema_version,
                "case_id": case.case_id,
                "attack_class": case.attack_class,
                "input": case.input,
                "expected_risk": case.expected_risk,
                "rationale": case.rationale,
                "assertions": list(case.assertions),
            }
            for case in corpus.cases
        ],
    }


def _canonical_json_bytes(value: object) -> bytes:
    text = json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    )
    return text.encode("utf-8") + b"\n"


def validate_corpus(raw: object) -> Corpus:
    payload = _validate_keys(raw, _PAYLOAD_FIELDS, _PAYLOAD_FIELDS, "corpus")
    schema_version = payload["schema_version"]
    if schema_version != CORPUS_SCHEMA_VERSION:
        _fail("corpus.schema_version", f"must equal {CORPUS_SCHEMA_VERSION}")

    metadata = _validate_metadata(payload["generation_metadata"])
    cases_raw = payload["cases"]
    if not isinstance(cases_raw, list):
        _fail("corpus.cases", "must be an array")
    if len(cases_raw) < MIN_CASE_COUNT or len(cases_raw) > MAX_CASE_COUNT:
        _fail("corpus.cases", f"must contain between {MIN_CASE_COUNT} and {MAX_CASE_COUNT} cases")

    cases = tuple(_validate_case(value, index) for index, value in enumerate(cases_raw))
    case_ids = [case.case_id for case in cases]
    if len(case_ids) != len(set(case_ids)):
        _fail("corpus.cases", "case_id values must be unique")
    represented = {case.attack_class for case in cases}
    missing = [value for value in ATTACK_CLASSES if value not in represented]
    if missing:
        _fail("corpus.cases", f"must represent attack class: {missing[0]}")
    if metadata.generated_case_count != len(cases):
        _fail("corpus.generation_metadata.generated_case_count", "must equal len(cases)")

    ordered_cases = tuple(sorted(cases, key=lambda case: case.case_id))
    provisional = Corpus(schema_version, metadata, ordered_cases, "")
    digest = hashlib.sha256(_canonical_json_bytes(_payload_object(provisional))).hexdigest()
    return Corpus(schema_version, metadata, ordered_cases, digest)


def canonical_payload_bytes(corpus: Corpus) -> bytes:
    if not isinstance(corpus, Corpus):
        _fail("corpus", "must be a validated Corpus")
    normalized = validate_corpus(_payload_object(corpus))
    return _canonical_json_bytes(_payload_object(normalized))


def canonical_persisted_bytes(corpus: Corpus) -> bytes:
    normalized = validate_corpus(_payload_object(corpus))
    persisted = _payload_object(normalized)
    persisted["corpus_sha256"] = normalized.corpus_sha256
    return _canonical_json_bytes(persisted)


def _path_string(path: str | os.PathLike[str]) -> str:
    try:
        return os.fspath(path)
    except TypeError:
        _fail("corpus path", "must be path-like")


def persist_corpus(raw: object, path: str | os.PathLike[str]) -> Corpus:
    if isinstance(raw, Corpus):
        corpus = validate_corpus(_payload_object(raw))
    else:
        corpus = validate_corpus(raw)
    data = canonical_persisted_bytes(corpus)
    destination = _path_string(path)

    try:
        atomic_write_bytes(destination, data, overwrite=False)
    except FileExistsError:
        _fail("corpus path", "destination already exists")
    except OSError:
        _fail("corpus", "atomic persistence failed")

    try:
        verified = load_corpus(destination)
    except CorpusValidationError:
        try:
            Path(destination).unlink()
        except OSError:
            _fail("corpus", "read-back verification and cleanup failed")
        _fail("corpus", "read-back verification failed")
    if verified != corpus:
        try:
            Path(destination).unlink()
        except OSError:
            _fail("corpus", "read-back verification and cleanup failed")
        _fail("corpus", "read-back verification failed")
    return verified


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")


def load_corpus(path: str | os.PathLike[str]) -> Corpus:
    source = _path_string(path)
    try:
        data = Path(source).read_bytes()
    except FileNotFoundError:
        _fail("corpus", "file not found")
    except OSError:
        _fail("corpus", "file could not be read")

    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        _fail("corpus", "invalid UTF-8")
    try:
        raw = json.loads(text, parse_constant=_reject_json_constant)
    except (json.JSONDecodeError, ValueError):
        _fail("corpus", "invalid JSON")

    persisted = _validate_keys(raw, _PERSISTED_FIELDS, _PERSISTED_FIELDS, "corpus")
    payload = {field: persisted[field] for field in _PAYLOAD_FIELDS}
    corpus = validate_corpus(payload)

    stored_sha256 = persisted["corpus_sha256"]
    if not isinstance(stored_sha256, str) or not _SHA256_RE.fullmatch(stored_sha256):
        _fail("corpus.corpus_sha256", "must be 64 lowercase hexadecimal characters")
    if not hmac.compare_digest(stored_sha256, corpus.corpus_sha256):
        _fail("corpus.corpus_sha256", "does not match canonical payload")
    if data != canonical_persisted_bytes(corpus):
        _fail("corpus", "file is not in canonical persisted form")
    return corpus
