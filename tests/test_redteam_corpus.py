from __future__ import annotations

import copy
import json
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

import llmfuzz.io as llmfuzz_io
import llmfuzz.redteam_corpus as corpus_module
from llmfuzz.redteam_corpus import (
    ASSERTION_VOCABULARY,
    ATTACK_CLASSES,
    CASE_SCHEMA_VERSION,
    CORPUS_SCHEMA_VERSION,
    MAX_CASE_ID_CHARS,
    MAX_INPUT_CHARS,
    MAX_RATIONALE_CHARS,
    CorpusValidationError,
    canonical_payload_bytes,
    canonical_persisted_bytes,
    load_corpus,
    persist_corpus,
    validate_corpus,
)


def _raw_corpus(count: int = 12) -> dict[str, object]:
    cases = []
    for index in range(count):
        cases.append(
            {
                "schema_version": CASE_SCHEMA_VERSION,
                "case_id": f"case_{index:02d}",
                "attack_class": ATTACK_CLASSES[index % len(ATTACK_CLASSES)],
                "input": f"Synthetic adversarial input {index}",
                "expected_risk": "critical",
                "rationale": f"Synthetic rationale {index}",
                "assertions": [ASSERTION_VOCABULARY[index % len(ASSERTION_VOCABULARY)]],
            }
        )
    return {
        "schema_version": CORPUS_SCHEMA_VERSION,
        "generation_metadata": {
            "model": "synthetic-model",
            "openai_response_id": "resp_synthetic_001",
            "prompt_sha256": "a" * 64,
            "output_schema_version": CORPUS_SCHEMA_VERSION,
            "generation_timestamp": "2026-07-18T12:34:56Z",
            "requested_case_count": count,
            "generated_case_count": count,
            "token_usage": {
                "input_tokens": 100,
                "output_tokens": 200,
                "total_tokens": 300,
            },
        },
        "cases": cases,
    }


def _at(raw: object, path: tuple[object, ...]) -> object:
    value = raw
    for part in path:
        value = value[part]  # type: ignore[index]
    return value


@pytest.mark.parametrize("count", [12, 20])
def test_valid_corpus_bounds_and_closed_vocabularies(count: int) -> None:
    raw = _raw_corpus(count)
    raw["cases"][0]["assertions"] = list(reversed(ASSERTION_VOCABULARY))  # type: ignore[index]

    corpus = validate_corpus(raw)

    assert len(corpus.cases) == count
    assert {case.attack_class for case in corpus.cases} == set(ATTACK_CLASSES)
    assert set(corpus.cases[0].assertions) == set(ASSERTION_VOCABULARY)


def test_validated_corpus_is_immutable() -> None:
    corpus = validate_corpus(_raw_corpus())

    with pytest.raises(FrozenInstanceError):
        corpus.schema_version = "changed"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        corpus.cases[0].case_id = "changed"  # type: ignore[misc]


@pytest.mark.parametrize(
    ("path", "field"),
    [
        ((), "schema_version"),
        (("generation_metadata",), "model"),
        (("cases", 0), "input"),
    ],
)
def test_missing_required_field_is_rejected(path: tuple[object, ...], field: str) -> None:
    raw = _raw_corpus()
    del _at(raw, path)[field]  # type: ignore[index]

    with pytest.raises(CorpusValidationError, match="missing required field"):
        validate_corpus(raw)


@pytest.mark.parametrize("path", [(), ("generation_metadata",), ("cases", 0)])
def test_unknown_field_is_rejected(path: tuple[object, ...]) -> None:
    raw = _raw_corpus()
    _at(raw, path)["unexpected"] = True  # type: ignore[index]

    with pytest.raises(CorpusValidationError, match="unknown field"):
        validate_corpus(raw)


@pytest.mark.parametrize(
    ("path", "value", "message"),
    [
        (("schema_version",), "wrong", "corpus.schema_version"),
        (("cases", 0, "schema_version"), "wrong", "cases\\[0\\].schema_version"),
        (("cases", 0, "attack_class"), "new class", "attack_class"),
        (("cases", 0, "expected_risk"), "high", "expected_risk"),
        (("generation_metadata", "output_schema_version"), "wrong", "output_schema_version"),
    ],
)
def test_closed_schema_and_enum_values_are_enforced(
    path: tuple[object, ...], value: object, message: str
) -> None:
    raw = _raw_corpus()
    parent = _at(raw, path[:-1])
    parent[path[-1]] = value  # type: ignore[index]

    with pytest.raises(CorpusValidationError, match=message):
        validate_corpus(raw)


def test_every_attack_class_is_required() -> None:
    raw = _raw_corpus()
    for case in raw["cases"]:  # type: ignore[union-attr]
        if case["attack_class"] == "approval bypass":
            case["attack_class"] = "prompt injection"

    with pytest.raises(CorpusValidationError, match="must represent attack class: approval bypass"):
        validate_corpus(raw)


def test_duplicate_case_id_is_rejected() -> None:
    raw = _raw_corpus()
    raw["cases"][1]["case_id"] = raw["cases"][0]["case_id"]  # type: ignore[index]

    with pytest.raises(CorpusValidationError, match="case_id values must be unique"):
        validate_corpus(raw)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("case_id", "", "case_id"),
        ("case_id", "   ", "case_id"),
        ("case_id", "Unsafe/ID", "case_id"),
        ("case_id", "a" * (MAX_CASE_ID_CHARS + 1), "case_id"),
        ("input", "", "input"),
        ("input", "x" * (MAX_INPUT_CHARS + 1), "input"),
        ("rationale", " ", "rationale"),
        ("rationale", "x" * (MAX_RATIONALE_CHARS + 1), "rationale"),
    ],
)
def test_case_string_constraints(field: str, value: str, message: str) -> None:
    raw = _raw_corpus()
    raw["cases"][0][field] = value  # type: ignore[index]

    with pytest.raises(CorpusValidationError, match=message):
        validate_corpus(raw)


@pytest.mark.parametrize(
    ("assertions", "message"),
    [
        ([], "must not be empty"),
        ([ASSERTION_VOCABULARY[0], ASSERTION_VOCABULARY[0]], "duplicates"),
        (["unknown_assertion"], "unknown assertion"),
    ],
)
def test_assertion_constraints(assertions: list[str], message: str) -> None:
    raw = _raw_corpus()
    raw["cases"][0]["assertions"] = assertions  # type: ignore[index]

    with pytest.raises(CorpusValidationError, match=message):
        validate_corpus(raw)


@pytest.mark.parametrize("count", [11, 21])
def test_corpus_cardinality_is_bounded(count: int) -> None:
    raw = _raw_corpus(12)
    raw["cases"] = raw["cases"][:count] if count < 12 else raw["cases"] + copy.deepcopy(raw["cases"][:9])  # type: ignore[index,operator]

    with pytest.raises(CorpusValidationError, match="must contain between 12 and 20 cases"):
        validate_corpus(raw)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("requested_case_count", 11, "requested_case_count"),
        ("generated_case_count", 21, "generated_case_count"),
        ("requested_case_count", 13, "must equal generated_case_count"),
        ("generated_case_count", 13, "must equal len\\(cases\\)"),
        ("requested_case_count", True, "must be an integer"),
    ],
)
def test_generation_count_constraints(field: str, value: object, message: str) -> None:
    raw = _raw_corpus()
    raw["generation_metadata"][field] = value  # type: ignore[index]
    if field == "generated_case_count" and value == 13:
        raw["generation_metadata"]["requested_case_count"] = 13  # type: ignore[index]

    with pytest.raises(CorpusValidationError, match=message):
        validate_corpus(raw)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("prompt_sha256", "A" * 64, "64 lowercase hexadecimal"),
        ("prompt_sha256", "a" * 63, "64 lowercase hexadecimal"),
        ("generation_timestamp", "2026-07-18T12:34:56+00:00", "UTC timestamp"),
        ("generation_timestamp", "2026-02-30T12:34:56Z", "valid UTC timestamp"),
    ],
)
def test_metadata_format_constraints(field: str, value: object, message: str) -> None:
    raw = _raw_corpus()
    raw["generation_metadata"][field] = value  # type: ignore[index]

    with pytest.raises(CorpusValidationError, match=message):
        validate_corpus(raw)


@pytest.mark.parametrize(
    ("token_usage", "message"),
    [
        ({"input_tokens": -1, "output_tokens": 2, "total_tokens": 1}, "greater than or equal"),
        ({"input_tokens": True, "output_tokens": 2, "total_tokens": 3}, "must be an integer"),
        ({"input_tokens": 1, "output_tokens": 2, "total_tokens": 4}, "must equal"),
        ({"input_tokens": 1, "output_tokens": 2}, "missing required field"),
        ({"input_tokens": 1, "output_tokens": 2, "total_tokens": 3, "extra": 0}, "unknown field"),
    ],
)
def test_token_usage_constraints(token_usage: object, message: str) -> None:
    raw = _raw_corpus()
    raw["generation_metadata"]["token_usage"] = token_usage  # type: ignore[index]

    with pytest.raises(CorpusValidationError, match=message):
        validate_corpus(raw)


@pytest.mark.parametrize("token_usage", [None, "absent"])
def test_token_usage_may_be_null_or_absent(token_usage: object) -> None:
    raw = _raw_corpus()
    if token_usage == "absent":
        del raw["generation_metadata"]["token_usage"]  # type: ignore[index]
    else:
        raw["generation_metadata"]["token_usage"] = None  # type: ignore[index]

    assert validate_corpus(raw).generation_metadata.token_usage is None


def _reversed_mapping_order(value: object) -> object:
    if isinstance(value, dict):
        return {key: _reversed_mapping_order(value[key]) for key in reversed(list(value))}
    if isinstance(value, list):
        return [_reversed_mapping_order(item) for item in value]
    return value


@pytest.mark.parametrize("variation", ["mapping", "cases", "assertions"])
def test_canonical_identity_ignores_semantically_irrelevant_order(variation: str) -> None:
    raw = _raw_corpus()
    reordered = copy.deepcopy(raw)
    if variation == "mapping":
        reordered = _reversed_mapping_order(reordered)
    elif variation == "cases":
        reordered["cases"] = list(reversed(reordered["cases"]))  # type: ignore[index]
    else:
        raw["cases"][0]["assertions"] = list(ASSERTION_VOCABULARY)  # type: ignore[index]
        reordered["cases"][0]["assertions"] = list(reversed(ASSERTION_VOCABULARY))  # type: ignore[index]

    first = validate_corpus(raw)
    second = validate_corpus(reordered)

    assert canonical_payload_bytes(first) == canonical_payload_bytes(second)
    assert first.corpus_sha256 == second.corpus_sha256


def test_meaningful_change_changes_identity() -> None:
    first_raw = _raw_corpus()
    second_raw = copy.deepcopy(first_raw)
    second_raw["cases"][0]["input"] = "Changed synthetic input"  # type: ignore[index]

    assert validate_corpus(first_raw).corpus_sha256 != validate_corpus(second_raw).corpus_sha256


def test_canonical_bytes_are_compact_utf8_with_one_trailing_newline() -> None:
    raw = _raw_corpus()
    raw["cases"][0]["input"] = "Unicode snowman ☃"  # type: ignore[index]
    data = canonical_payload_bytes(validate_corpus(raw))

    assert data.endswith(b"\n")
    assert data.count(b"\n") == 1
    assert b"\n  " not in data
    assert "☃".encode("utf-8") in data


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_nonfinite_numbers_cannot_enter_canonical_representation(value: float) -> None:
    raw = _raw_corpus()
    raw["generation_metadata"]["token_usage"]["input_tokens"] = value  # type: ignore[index]

    with pytest.raises(CorpusValidationError, match="must be an integer"):
        validate_corpus(raw)


def test_persist_and_load_nested_path_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "corpus.json"
    corpus = persist_corpus(_raw_corpus(), path)

    assert path.exists()
    assert load_corpus(path) == corpus
    assert path.read_bytes() == canonical_persisted_bytes(corpus)


def test_save_load_and_reconstruction_preserve_identity_and_bytes(tmp_path: Path) -> None:
    first_path = tmp_path / "first.json"
    second_path = tmp_path / "second.json"
    first = persist_corpus(_raw_corpus(), first_path)
    loaded = load_corpus(first_path)
    second = persist_corpus(loaded, second_path)

    assert first.corpus_sha256 == loaded.corpus_sha256 == second.corpus_sha256
    assert first_path.read_bytes() == second_path.read_bytes()


def test_overwrite_is_rejected_by_default(tmp_path: Path) -> None:
    path = tmp_path / "corpus.json"
    original = b"existing\n"
    path.write_bytes(original)

    with pytest.raises(CorpusValidationError, match="destination already exists"):
        persist_corpus(_raw_corpus(), path)

    assert path.read_bytes() == original


def _write_json_bytes(path: Path, raw: object, *, sort_keys: bool = True, indent: int | None = None) -> None:
    path.write_bytes(
        (json.dumps(raw, ensure_ascii=False, sort_keys=sort_keys, separators=(",", ":") if indent is None else None, indent=indent) + "\n").encode("utf-8")
    )


def test_tampered_payload_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "corpus.json"
    persist_corpus(_raw_corpus(), path)
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["cases"][0]["input"] = "tampered"
    _write_json_bytes(path, raw)

    with pytest.raises(CorpusValidationError, match="does not match canonical payload"):
        load_corpus(path)


def test_tampered_hash_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "corpus.json"
    persist_corpus(_raw_corpus(), path)
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["corpus_sha256"] = "0" * 64
    _write_json_bytes(path, raw)

    with pytest.raises(CorpusValidationError, match="does not match canonical payload"):
        load_corpus(path)


@pytest.mark.parametrize("variation", ["pretty", "ordering", "missing-newline", "extra-newline"])
def test_noncanonical_persisted_bytes_are_rejected(tmp_path: Path, variation: str) -> None:
    path = tmp_path / "corpus.json"
    persist_corpus(_raw_corpus(), path)
    raw = json.loads(path.read_text(encoding="utf-8"))
    if variation == "pretty":
        _write_json_bytes(path, raw, indent=2)
    elif variation == "ordering":
        _write_json_bytes(path, {key: raw[key] for key in reversed(list(raw))}, sort_keys=False)
    elif variation == "missing-newline":
        path.write_bytes(path.read_bytes()[:-1])
    else:
        path.write_bytes(path.read_bytes() + b"\n")

    with pytest.raises(CorpusValidationError, match="not in canonical persisted form"):
        load_corpus(path)


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (b"\xff\n", "invalid UTF-8"),
        (b"{invalid}\n", "invalid JSON"),
        (b"[]\n", "must be an object"),
    ],
)
def test_invalid_file_content_is_rejected(tmp_path: Path, data: bytes, message: str) -> None:
    path = tmp_path / "corpus.json"
    path.write_bytes(data)

    with pytest.raises(CorpusValidationError, match=message):
        load_corpus(path)


@pytest.mark.parametrize("variation", ["missing", "unknown", "invalid-hash"])
def test_persisted_top_level_contract_is_strict(tmp_path: Path, variation: str) -> None:
    path = tmp_path / "corpus.json"
    persist_corpus(_raw_corpus(), path)
    raw = json.loads(path.read_text(encoding="utf-8"))
    if variation == "missing":
        del raw["corpus_sha256"]
        message = "missing required field"
    elif variation == "unknown":
        raw["unexpected"] = True
        message = "unknown field"
    else:
        raw["corpus_sha256"] = "not-a-sha256"
        message = "64 lowercase hexadecimal"
    _write_json_bytes(path, raw)

    with pytest.raises(CorpusValidationError, match=message):
        load_corpus(path)


def test_missing_file_error_is_sanitized(tmp_path: Path) -> None:
    path = tmp_path / "secret-looking-name.json"

    with pytest.raises(CorpusValidationError) as exc_info:
        load_corpus(path)

    assert str(exc_info.value) == "corpus: file not found"
    assert str(path) not in str(exc_info.value)


def test_failed_validation_leaves_no_artifact(tmp_path: Path) -> None:
    path = tmp_path / "corpus.json"
    raw = _raw_corpus()
    raw["cases"] = []

    with pytest.raises(CorpusValidationError):
        persist_corpus(raw, path)

    assert not path.exists()


def test_serialization_failure_leaves_no_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "corpus.json"

    def fail_serialization(value: object) -> bytes:
        raise ValueError("synthetic serialization failure")

    monkeypatch.setattr(corpus_module, "_canonical_json_bytes", fail_serialization)
    with pytest.raises(ValueError, match="synthetic serialization failure"):
        persist_corpus(_raw_corpus(), path)

    assert not path.exists()


def test_atomic_failure_cleans_temporary_file_and_leaves_no_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "nested" / "corpus.json"

    def fail_link(source: str, destination: str) -> None:
        raise OSError("synthetic atomic failure")

    monkeypatch.setattr(llmfuzz_io.os, "link", fail_link)
    with pytest.raises(CorpusValidationError, match="atomic persistence failed"):
        persist_corpus(_raw_corpus(), path)

    assert not path.exists()
    assert list(path.parent.glob(".tmp.*")) == []


def test_failed_readback_removes_new_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "corpus.json"

    def fail_load(source: str | Path) -> object:
        raise CorpusValidationError("synthetic read-back failure")

    monkeypatch.setattr(corpus_module, "load_corpus", fail_load)
    with pytest.raises(CorpusValidationError, match="read-back verification failed"):
        persist_corpus(_raw_corpus(), path)

    assert not path.exists()


def test_exclusive_atomic_writer_cleans_temp_on_publish_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "bytes.bin"

    def fail_link(source: str, destination: str) -> None:
        raise OSError("synthetic link failure")

    monkeypatch.setattr(llmfuzz_io.os, "link", fail_link)
    with pytest.raises(OSError, match="synthetic link failure"):
        llmfuzz_io.atomic_write_bytes(path, b"content", overwrite=False)

    assert not path.exists()
    assert list(tmp_path.glob(".tmp.*")) == []


def test_exclusive_atomic_writer_publishes_exact_bytes(tmp_path: Path) -> None:
    path = tmp_path / "bytes.bin"

    llmfuzz_io.atomic_write_bytes(path, b"published", overwrite=False)

    assert path.read_bytes() == b"published"
    assert list(tmp_path.glob(".tmp.*")) == []


def test_exclusive_atomic_writer_preserves_existing_destination(tmp_path: Path) -> None:
    path = tmp_path / "bytes.bin"
    path.write_bytes(b"original")

    with pytest.raises(FileExistsError):
        llmfuzz_io.atomic_write_bytes(path, b"replacement", overwrite=False)

    assert path.read_bytes() == b"original"
    assert list(tmp_path.glob(".tmp.*")) == []


def test_exclusive_atomic_writer_keeps_success_after_post_publish_cleanup_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "bytes.bin"
    real_unlink = llmfuzz_io.os.unlink
    cleanup_failures = 0

    def fail_first_temp_cleanup(candidate: str) -> None:
        nonlocal cleanup_failures
        if Path(candidate).name.startswith(".tmp.") and cleanup_failures == 0:
            cleanup_failures += 1
            raise OSError("synthetic post-publication cleanup failure")
        real_unlink(candidate)

    monkeypatch.setattr(llmfuzz_io.os, "unlink", fail_first_temp_cleanup)

    llmfuzz_io.atomic_write_bytes(path, b"published", overwrite=False)

    assert cleanup_failures == 1
    assert path.read_bytes() == b"published"


def test_atomic_byte_writer_uses_mkstemp_in_destination_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "nested" / "bytes.bin"
    real_mkstemp = llmfuzz_io.tempfile.mkstemp
    calls: list[dict[str, object]] = []

    def record_mkstemp(*args: object, **kwargs: object) -> tuple[int, str]:
        calls.append(dict(kwargs))
        return real_mkstemp(*args, **kwargs)

    monkeypatch.setattr(llmfuzz_io.tempfile, "mkstemp", record_mkstemp)

    llmfuzz_io.atomic_write_bytes(path, b"content", overwrite=False)

    assert len(calls) == 1
    assert calls[0]["dir"] == str(path.parent)
    assert str(calls[0]["prefix"]).startswith(".tmp.")
    assert path.read_bytes() == b"content"


def test_atomic_byte_writer_default_overwrite_behavior_is_unchanged(tmp_path: Path) -> None:
    path = tmp_path / "bytes.bin"
    path.write_bytes(b"original")

    llmfuzz_io.atomic_write_bytes(path, b"replacement")

    assert path.read_bytes() == b"replacement"
    assert list(tmp_path.glob(".tmp.*")) == []
