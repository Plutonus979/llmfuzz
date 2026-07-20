from __future__ import annotations

import builtins
import json
import os
import shutil
import socket
import stat
import subprocess
import sys
from collections import Counter
from dataclasses import FrozenInstanceError, fields
from pathlib import Path

import pytest

import llmfuzz.cli as cli
import llmfuzz.redteam_demo_target as demo_target
import llmfuzz.redteam_evaluation as evaluation
import llmfuzz.redteam_generation as generation
import llmfuzz.redteam_openai as redteam_openai
import llmfuzz.redteam_run as redteam_run
from llmfuzz.redteam_contracts import (
    CASE_RESULT_SCHEMA_VERSION,
    EVENT_SCHEMA_VERSION,
    INVARIANT_RESULT_SCHEMA_VERSION,
    TARGET_INPUT_SCHEMA_VERSION,
    ContractValidationError,
    canonical_contract_bytes,
    target_input_from_case,
    validate_event,
)
from llmfuzz.redteam_corpus import (
    ACCEPTED_CORPUS_SHA256,
    ASSERTION_VOCABULARY,
    CASE_SCHEMA_VERSION,
    EXPECTED_RISK,
    CorpusCase,
    load_bundled_accepted_corpus,
)
from llmfuzz.redteam_demo_target import (
    FIXED_TARGET_ID,
    MAX_TARGET_INPUT_BYTES,
    MAX_TARGET_OUTPUT_BYTES,
    TARGET_OUTPUT_SCHEMA_VERSION,
    VULNERABLE_TARGET_ID,
)
from llmfuzz.redteam_evaluation import (
    MAX_CASE_RESULT_BYTES,
    MAX_CORPUS_REFERENCE_BYTES,
    MAX_EVALUATION_PATH_CHARS,
    MAX_EXECUTABLE_PATH_CHARS,
    MAX_EXECUTION_METADATA_BYTES,
    MAX_RUN_MANIFEST_BYTES,
    EvaluatedCase,
    RedTeamEvaluationError,
    RedTeamEvaluationResult,
    RedTeamEvaluationValidationError,
    evaluate_persisted_run,
)
from llmfuzz.redteam_run import (
    ACCEPTED_PERSISTED_SHA256,
    CORPUS_REFERENCE_SCHEMA_VERSION,
    EXECUTION_SCHEMA_VERSION,
    EXECUTION_STATUSES,
    MAX_TARGET_STDERR_BYTES,
    RUN_MANIFEST_SCHEMA_VERSION,
    TARGET_TIMEOUT_SECONDS,
    run_accepted_corpus,
)


def _canonical(value: object) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        + b"\n"
    )


@pytest.fixture(scope="module")
def evidence_templates(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    root = tmp_path_factory.mktemp("d2-evidence")
    templates: dict[str, Path] = {}
    for target in ("vulnerable", "fixed"):
        output = root / target
        result = run_accepted_corpus(target=target, output=output)
        assert result.completed is True
        templates[target] = output
    return templates


def _copy_run(tmp_path: Path, template: Path) -> Path:
    root = tmp_path / "run"
    shutil.copytree(template, root)
    return root


def _manifest_path(root: Path) -> Path:
    return root / "llmfuzz" / "redteam-run.json"


def _load(path: Path) -> dict[str, object]:
    raw = json.loads(path.read_bytes())
    assert isinstance(raw, dict)
    return raw


def _write(path: Path, raw: object) -> None:
    path.write_bytes(_canonical(raw))


def _manifest(root: Path) -> dict[str, object]:
    return _load(_manifest_path(root))


def _records(root: Path) -> list[dict[str, object]]:
    raw = _manifest(root)["cases"]
    assert isinstance(raw, list)
    assert all(isinstance(item, dict) for item in raw)
    return raw  # type: ignore[return-value]


def _record(root: Path, index: int = 0) -> dict[str, object]:
    return _records(root)[index]


def _run_dir(root: Path, index: int = 0) -> Path:
    return root / str(_record(root, index)["run_path"])


def _exec_path(root: Path, index: int = 0) -> Path:
    return root / str(_record(root, index)["exec_path"])


def _rewrite_manifest(root: Path, mutate) -> None:
    raw = _manifest(root)
    mutate(raw)
    _write(_manifest_path(root), raw)


def _rewrite_exec(root: Path, mutate, index: int = 0) -> None:
    path = _exec_path(root, index)
    raw = _load(path)
    mutate(raw)
    _write(path, raw)


_STATUS_EXECUTION = {
    "completed": (None, 0, "exec/redteam-events.json"),
    "timeout": ("timeout", -15, None),
    "stdout_limit": ("stdout_limit", -15, None),
    "stderr_limit": ("stderr_limit", -15, None),
    "nonzero_exit": ("nonzero_exit", 7, None),
    "launch_error": ("process_io_error", None, None),
    "malformed_output": ("target_output_invalid", 0, None),
    "blocked": ("blocked", None, None),
}

_INVALID_STATUS_METADATA = (
    ("completed", "error_code", "unexpected"),
    ("completed", "exit_code", 0.0),
    ("completed", "exit_code", 1),
    ("completed", "events_path", None),
    ("completed", "timed_out", True),
    ("completed", "stdout_limit_exceeded", True),
    ("completed", "stderr_limit_exceeded", True),
    ("completed", "manifest_status", "timeout"),
    ("timeout", "error_code", "unexpected"),
    ("timeout", "exit_code", -15.0),
    ("timeout", "events_path", "exec/redteam-events.json"),
    ("timeout", "timed_out", False),
    ("timeout", "stdout_limit_exceeded", True),
    ("timeout", "stderr_limit_exceeded", True),
    ("timeout", "manifest_status", "completed"),
    ("stdout_limit", "error_code", "unexpected"),
    ("stdout_limit", "exit_code", -15.0),
    ("stdout_limit", "events_path", "exec/redteam-events.json"),
    ("stdout_limit", "timed_out", True),
    ("stdout_limit", "stdout_limit_exceeded", False),
    ("stdout_limit", "stderr_limit_exceeded", True),
    ("stdout_limit", "manifest_status", "completed"),
    ("stderr_limit", "error_code", "unexpected"),
    ("stderr_limit", "exit_code", -15.0),
    ("stderr_limit", "events_path", "exec/redteam-events.json"),
    ("stderr_limit", "timed_out", True),
    ("stderr_limit", "stdout_limit_exceeded", True),
    ("stderr_limit", "stderr_limit_exceeded", False),
    ("stderr_limit", "manifest_status", "completed"),
    ("nonzero_exit", "error_code", "unexpected"),
    ("nonzero_exit", "exit_code", 7.0),
    ("nonzero_exit", "exit_code", 0),
    ("nonzero_exit", "events_path", "exec/redteam-events.json"),
    ("nonzero_exit", "timed_out", True),
    ("nonzero_exit", "stdout_limit_exceeded", True),
    ("nonzero_exit", "stderr_limit_exceeded", True),
    ("nonzero_exit", "manifest_status", "completed"),
    ("launch_error", "error_code", None),
    ("launch_error", "exit_code", 7.0),
    ("launch_error", "events_path", "exec/redteam-events.json"),
    ("launch_error", "timed_out", True),
    ("launch_error", "stdout_limit_exceeded", True),
    ("launch_error", "stderr_limit_exceeded", True),
    ("launch_error", "manifest_status", "completed"),
    ("malformed_output", "error_code", None),
    ("malformed_output", "exit_code", 0.0),
    ("malformed_output", "exit_code", 1),
    ("malformed_output", "events_path", "exec/redteam-events.json"),
    ("malformed_output", "timed_out", True),
    ("malformed_output", "stdout_limit_exceeded", True),
    ("malformed_output", "stderr_limit_exceeded", True),
    ("malformed_output", "manifest_status", "completed"),
    ("blocked", "error_code", "unexpected"),
    ("blocked", "exit_code", 7.0),
    ("blocked", "events_path", "exec/redteam-events.json"),
    ("blocked", "timed_out", True),
    ("blocked", "stdout_limit_exceeded", True),
    ("blocked", "stderr_limit_exceeded", True),
    ("blocked", "manifest_status", "completed"),
)


def _set_status(root: Path, status: str, index: int = 0) -> None:
    record = _record(root, index)
    record["status"] = status
    record["events_path"] = (
        f"{record['run_path']}/exec/redteam-events.json"
        if status == "completed"
        else None
    )
    manifest = _manifest(root)
    manifest_records = manifest["cases"]
    assert isinstance(manifest_records, list)
    manifest_records[index] = record
    _write(_manifest_path(root), manifest)

    error_code, exit_code, events_path = _STATUS_EXECUTION[status]

    def mutate(execution: dict[str, object]) -> None:
        execution.update(
            {
                "error_code": error_code,
                "events_path": events_path,
                "exit_code": exit_code,
                "status": status,
                "timed_out": status == "timeout",
                "stdout_limit_exceeded": status == "stdout_limit",
                "stderr_limit_exceeded": status == "stderr_limit",
            }
        )

    _rewrite_exec(root, mutate, index)
    events = _run_dir(root, index) / "exec" / "redteam-events.json"
    if status != "completed" and os.path.lexists(events):
        events.unlink()
    if status == "malformed_output":
        (_run_dir(root, index) / "exec" / "stdout.txt").write_bytes(b"not-json\n")


def _assert_rejected(root: object, code: str = "run_rejected") -> None:
    with pytest.raises(RedTeamEvaluationValidationError) as exc_info:
        evaluate_persisted_run(root)  # type: ignore[arg-type]
    assert exc_info.value.code == code
    assert str(exc_info.value) in {
        "Red Team evaluation input validation failed.",
        "Existing Red Team evaluation result conflicts with deterministic output.",
        "Red Team evaluation destination is invalid.",
    }


def _event(event_type: str, **payload: object):
    return validate_event(
        {
            "schema_version": EVENT_SCHEMA_VERSION,
            "event_type": event_type,
            "payload": payload,
        }
    )


def _final(disposition: str = "completed"):
    return _event("final", disposition=disposition)


def _case_for(assertion: str) -> CorpusCase:
    corpus = load_bundled_accepted_corpus()
    return next(case for case in corpus.cases if assertion in case.assertions)


def test_public_literals_models_and_errors_are_locked() -> None:
    assert ACCEPTED_CORPUS_SHA256 == (
        "9dd6f3675d18926610ea4b8da2f580dd48b52cb1e9002cce1198df6961167140"
    )
    assert ACCEPTED_PERSISTED_SHA256 == (
        "15d5a23bcd87cdf7c12a7557bf2c8d738199f5dd2a5c393c94d49462f412b461"
    )
    assert TARGET_INPUT_SCHEMA_VERSION == "llmfuzz.redteam.target-input.v1"
    assert EVENT_SCHEMA_VERSION == "llmfuzz.redteam.event.v1"
    assert INVARIANT_RESULT_SCHEMA_VERSION == "llmfuzz.redteam.invariant-result.v1"
    assert CASE_RESULT_SCHEMA_VERSION == "llmfuzz.redteam.case-result.v1"
    assert TARGET_OUTPUT_SCHEMA_VERSION == "llmfuzz.redteam.target-output.v1"
    assert CORPUS_REFERENCE_SCHEMA_VERSION == "llmfuzz.redteam.corpus-reference.v1"
    assert EXECUTION_SCHEMA_VERSION == "llmfuzz.redteam.execution.v1"
    assert RUN_MANIFEST_SCHEMA_VERSION == "llmfuzz.redteam.run.v1"
    assert VULNERABLE_TARGET_ID == "llmfuzz.redteam.demo-target.vulnerable.v1"
    assert FIXED_TARGET_ID == "llmfuzz.redteam.demo-target.fixed.v1"
    assert EXECUTION_STATUSES == (
        "completed",
        "timeout",
        "stdout_limit",
        "stderr_limit",
        "nonzero_exit",
        "launch_error",
        "malformed_output",
        "blocked",
    )
    assert MAX_EVALUATION_PATH_CHARS == 4_096
    assert MAX_RUN_MANIFEST_BYTES == 65_536
    assert MAX_CORPUS_REFERENCE_BYTES == 2_048
    assert MAX_EXECUTION_METADATA_BYTES == 16_384
    assert MAX_CASE_RESULT_BYTES == 65_536
    assert MAX_EXECUTABLE_PATH_CHARS == 4_096
    assert [field.name for field in fields(EvaluatedCase)] == [
        "case_id",
        "case_run_id",
        "execution_status",
        "execution_error_code",
        "result_path",
        "result",
    ]
    assert [field.name for field in fields(RedTeamEvaluationResult)] == [
        "output_root",
        "execution_id",
        "target_id",
        "corpus_sha256",
        "persisted_sha256",
        "cases",
    ]
    assert EvaluatedCase.__dataclass_params__.frozen is True
    assert RedTeamEvaluationResult.__dataclass_params__.frozen is True
    frozen_case = EvaluatedCase(
        "case", "run", "completed", None, Path("result"), None  # type: ignore[arg-type]
    )
    with pytest.raises(FrozenInstanceError):
        frozen_case.case_id = "changed"  # type: ignore[misc]
    for code, expected in (
        ("run_rejected", "Red Team evaluation input validation failed."),
        (
            "result_conflict",
            "Existing Red Team evaluation result conflicts with deterministic output.",
        ),
        ("destination_invalid", "Red Team evaluation destination is invalid."),
    ):
        error = RedTeamEvaluationValidationError(code)
        assert error.code == code
        assert str(error) == expected
    unknown_validation = RedTeamEvaluationValidationError("unknown")
    assert unknown_validation.code == "run_rejected"
    for code, expected in (
        (
            "artifact_persistence_failed",
            "Red Team evaluation evidence persistence failed.",
        ),
        ("evaluation_internal_error", "Red Team evaluation failed."),
    ):
        error = RedTeamEvaluationError(code)
        assert error.code == code
        assert str(error) == expected
    assert RedTeamEvaluationError("unknown").code == "evaluation_internal_error"


@pytest.mark.parametrize("target", ("vulnerable", "fixed"))
def test_valid_run_returns_all_canonical_results(
    tmp_path: Path,
    evidence_templates: dict[str, Path],
    target: str,
) -> None:
    root = _copy_run(tmp_path, evidence_templates[target])
    corpus = load_bundled_accepted_corpus()
    result = evaluate_persisted_run(root)

    assert result.output_root == Path(os.path.abspath(root))
    assert result.target_id == (
        VULNERABLE_TARGET_ID if target == "vulnerable" else FIXED_TARGET_ID
    )
    assert result.corpus_sha256 == ACCEPTED_CORPUS_SHA256
    assert result.persisted_sha256 == ACCEPTED_PERSISTED_SHA256
    assert [item.case_id for item in result.cases] == [
        case.case_id for case in corpus.cases
    ]
    assert len(result.cases) == 16
    for case, item in zip(corpus.cases, result.cases, strict=True):
        assert item.result_path.is_absolute()
        assert item.result_path.exists()
        assert item.result_path.read_bytes() == canonical_contract_bytes(
            item.result, case=case
        )


@pytest.mark.parametrize(
    "mutation",
    (
        "oversized",
        "empty",
        "utf8",
        "json",
        "nan",
        "infinity",
        "noncanonical",
        "unknown_field",
        "missing_field",
        "schema",
        "corpus",
        "persisted",
        "target",
        "execution_id",
        "case_count",
        "boolean_count",
        "duplicate_case",
        "duplicate_run",
        "missing_case",
        "extra_case",
        "order",
        "status",
    ),
)
def test_manifest_rejection_matrix(
    tmp_path: Path,
    evidence_templates: dict[str, Path],
    mutation: str,
) -> None:
    root = _copy_run(tmp_path, evidence_templates["fixed"])
    path = _manifest_path(root)
    raw = _manifest(root)
    records = raw["cases"]
    assert isinstance(records, list)
    if mutation == "oversized":
        path.write_bytes(b" " * (MAX_RUN_MANIFEST_BYTES + 1))
    elif mutation == "empty":
        path.write_bytes(b"")
    elif mutation == "utf8":
        path.write_bytes(b"\xff")
    elif mutation == "json":
        path.write_bytes(b"{\n")
    elif mutation == "nan":
        path.write_bytes(b'{"value":NaN}\n')
    elif mutation == "infinity":
        path.write_bytes(b'{"value":Infinity}\n')
    elif mutation == "noncanonical":
        path.write_text(json.dumps(raw, indent=2) + "\n", encoding="utf-8")
    elif mutation == "unknown_field":
        raw["unknown"] = True
        _write(path, raw)
    elif mutation == "missing_field":
        del raw["target_id"]
        _write(path, raw)
    elif mutation == "schema":
        raw["schema_version"] = "unknown"
        _write(path, raw)
    elif mutation == "corpus":
        raw["corpus_sha256"] = "0" * 64
        _write(path, raw)
    elif mutation == "persisted":
        raw["persisted_sha256"] = "0" * 64
        _write(path, raw)
    elif mutation == "target":
        raw["target_id"] = "unknown"
        _write(path, raw)
    elif mutation == "execution_id":
        raw["execution_id"] = "rt_" + "0" * 64
        _write(path, raw)
    elif mutation == "case_count":
        raw["case_count"] = 15
        _write(path, raw)
    elif mutation == "boolean_count":
        raw["case_count"] = True
        _write(path, raw)
    elif mutation == "duplicate_case":
        records[1]["case_id"] = records[0]["case_id"]  # type: ignore[index]
        _write(path, raw)
    elif mutation == "duplicate_run":
        records[1]["case_run_id"] = records[0]["case_run_id"]  # type: ignore[index]
        _write(path, raw)
    elif mutation == "missing_case":
        records.pop()
        raw["case_count"] = 15
        _write(path, raw)
    elif mutation == "extra_case":
        records.append(dict(records[-1]))  # type: ignore[arg-type]
        raw["case_count"] = 17
        _write(path, raw)
    elif mutation == "order":
        records[0], records[1] = records[1], records[0]
        _write(path, raw)
    else:
        records[0]["status"] = "unknown"  # type: ignore[index]
        _write(path, raw)
    _assert_rejected(root)
    assert list(root.glob("runs/*/eval/redteam-case-result.json")) == []


def test_missing_manifest_is_rejected(
    tmp_path: Path, evidence_templates: dict[str, Path]
) -> None:
    root = _copy_run(tmp_path, evidence_templates["fixed"])
    _manifest_path(root).unlink()
    _assert_rejected(root)


@pytest.mark.parametrize(
    "bad_root",
    (None, b"bytes", "", "bad\0root", "a/../b"),
)
def test_invalid_caller_roots_are_rejected(bad_root: object) -> None:
    _assert_rejected(bad_root)


def test_oversized_and_missing_roots_are_rejected(tmp_path: Path) -> None:
    _assert_rejected("x" * (MAX_EVALUATION_PATH_CHARS + 1))
    _assert_rejected(tmp_path / "missing")
    regular = tmp_path / "file"
    regular.write_text("x", encoding="utf-8")
    _assert_rejected(regular)


def test_root_and_ancestor_symlinks_are_rejected(
    tmp_path: Path, evidence_templates: dict[str, Path]
) -> None:
    real = _copy_run(tmp_path, evidence_templates["fixed"])
    root_link = tmp_path / "root-link"
    root_link.symlink_to(real, target_is_directory=True)
    _assert_rejected(root_link)

    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    nested = real_parent / "nested"
    shutil.copytree(evidence_templates["fixed"], nested)
    parent_link = tmp_path / "parent-link"
    parent_link.symlink_to(real_parent, target_is_directory=True)
    _assert_rejected(parent_link / "nested")


@pytest.mark.parametrize(
    "relative",
    ("llmfuzz", "runs", "runs/{id}", "runs/{id}/input", "runs/{id}/exec"),
)
def test_expected_directory_symlink_is_rejected(
    tmp_path: Path,
    evidence_templates: dict[str, Path],
    relative: str,
) -> None:
    root = _copy_run(tmp_path, evidence_templates["fixed"])
    run_id = str(_record(root)["case_run_id"])
    path = root / relative.format(id=run_id)
    saved = tmp_path / "saved"
    path.rename(saved)
    path.symlink_to(saved, target_is_directory=True)
    _assert_rejected(root)


def test_existing_eval_symlink_is_destination_invalid(
    tmp_path: Path, evidence_templates: dict[str, Path]
) -> None:
    root = _copy_run(tmp_path, evidence_templates["fixed"])
    eval_dir = _run_dir(root) / "eval"
    target = tmp_path / "outside"
    target.mkdir()
    eval_dir.symlink_to(target, target_is_directory=True)
    _assert_rejected(root, "destination_invalid")
    assert list(target.iterdir()) == []


def test_existing_nonwritable_eval_directory_is_destination_invalid(
    tmp_path: Path, evidence_templates: dict[str, Path]
) -> None:
    root = _copy_run(tmp_path, evidence_templates["fixed"])
    eval_dir = _run_dir(root) / "eval"
    eval_dir.mkdir(mode=0o555)
    try:
        _assert_rejected(root, "destination_invalid")
    finally:
        eval_dir.chmod(0o755)


def test_unusable_later_missing_eval_parent_prevents_every_result_write(
    tmp_path: Path, evidence_templates: dict[str, Path]
) -> None:
    root = _copy_run(tmp_path, evidence_templates["fixed"])
    assert list(root.glob("runs/*/eval/redteam-case-result.json")) == []
    late_parent = _run_dir(root, 15)
    assert not (late_parent / "eval").exists()
    late_parent.chmod(0o555)
    try:
        assert not os.access(
            late_parent,
            os.W_OK | os.X_OK,
            effective_ids=True,
        )
        _assert_rejected(root, "destination_invalid")
        assert list(root.glob("runs/*/eval/redteam-case-result.json")) == []
    finally:
        late_parent.chmod(0o755)


@pytest.mark.parametrize("kind", ("symlink", "broken", "directory"))
def test_source_artifact_unsafe_type_is_rejected(
    tmp_path: Path,
    evidence_templates: dict[str, Path],
    kind: str,
) -> None:
    root = _copy_run(tmp_path, evidence_templates["fixed"])
    path = _exec_path(root)
    path.unlink()
    if kind == "directory":
        path.mkdir()
    elif kind == "broken":
        path.symlink_to(tmp_path / "missing")
    else:
        target = tmp_path / "copy"
        target.write_bytes(b"{}\n")
        path.symlink_to(target)
    _assert_rejected(root)


def test_source_artifact_fifo_is_rejected_without_blocking(
    tmp_path: Path, evidence_templates: dict[str, Path]
) -> None:
    root = _copy_run(tmp_path, evidence_templates["fixed"])
    path = _exec_path(root)
    path.unlink()
    os.mkfifo(path)
    _assert_rejected(root)


@pytest.mark.parametrize("value", ("wrong/path", "/absolute/path", "../outside"))
def test_manifest_path_substitution_is_rejected_without_external_write(
    tmp_path: Path,
    evidence_templates: dict[str, Path],
    value: str,
) -> None:
    root = _copy_run(tmp_path, evidence_templates["fixed"])
    outside = tmp_path / "outside-result"

    def mutate(raw: dict[str, object]) -> None:
        records = raw["cases"]
        assert isinstance(records, list)
        records[0]["exec_path"] = value  # type: ignore[index]

    _rewrite_manifest(root, mutate)
    _assert_rejected(root)
    assert not outside.exists()


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("schema_version", "unknown"),
        ("case_count", 15),
        ("corpus_sha256", "0" * 64),
        ("persisted_sha256", "0" * 64),
    ),
)
def test_corpus_reference_tamper_is_rejected(
    tmp_path: Path,
    evidence_templates: dict[str, Path],
    field: str,
    value: object,
) -> None:
    root = _copy_run(tmp_path, evidence_templates["fixed"])
    path = _run_dir(root) / "llmfuzz" / "redteam-corpus-reference.json"
    raw = _load(path)
    raw[field] = value
    _write(path, raw)
    _assert_rejected(root)


@pytest.mark.parametrize("mutation", ("unknown", "noncanonical", "oversized", "different"))
def test_corpus_reference_shape_and_identity_are_exact(
    tmp_path: Path,
    evidence_templates: dict[str, Path],
    mutation: str,
) -> None:
    root = _copy_run(tmp_path, evidence_templates["fixed"])
    first = _run_dir(root) / "llmfuzz" / "redteam-corpus-reference.json"
    if mutation == "unknown":
        raw = _load(first)
        raw["unknown"] = True
        _write(first, raw)
    elif mutation == "noncanonical":
        first.write_text(json.dumps(_load(first), indent=2) + "\n", encoding="utf-8")
    elif mutation == "oversized":
        first.write_bytes(b"x" * (MAX_CORPUS_REFERENCE_BYTES + 1))
    else:
        first.write_bytes(first.read_bytes()[:-1] + b" ")
    _assert_rejected(root)


@pytest.mark.parametrize(
    "mutation",
    (
        "case_id",
        "attack_class",
        "input",
        "assertion",
        "assertion_order",
        "unknown",
        "noncanonical",
        "oversized",
        "other_case",
    ),
)
def test_target_input_exact_bytes_are_enforced(
    tmp_path: Path,
    evidence_templates: dict[str, Path],
    mutation: str,
) -> None:
    root = _copy_run(tmp_path, evidence_templates["fixed"])
    path = _run_dir(root) / "input" / "redteam-target-input.json"
    raw = _load(path)
    if mutation == "case_id":
        raw["case_id"] = "other-valid-case"
    elif mutation == "attack_class":
        raw["attack_class"] = "secret exfiltration"
    elif mutation == "input":
        raw["input"] = str(raw["input"]) + " changed"
    elif mutation == "assertion":
        raw["assertions"] = ["must_not_reveal_secret"]
    elif mutation == "assertion_order":
        raw["assertions"] = list(reversed(ASSERTION_VOCABULARY))
    elif mutation == "unknown":
        raw["unknown"] = True
    elif mutation == "noncanonical":
        path.write_text(json.dumps(raw, indent=2) + "\n", encoding="utf-8")
        _assert_rejected(root)
        return
    elif mutation == "oversized":
        path.write_bytes(b"x" * (MAX_TARGET_INPUT_BYTES + 1))
        _assert_rejected(root)
        return
    else:
        other_path = _run_dir(root, 1) / "input" / "redteam-target-input.json"
        path.write_bytes(other_path.read_bytes())
        _assert_rejected(root)
        return
    _write(path, raw)
    _assert_rejected(root)


@pytest.mark.parametrize("status", EXECUTION_STATUSES)
def test_every_execution_status_has_one_valid_exact_combination(
    tmp_path: Path,
    evidence_templates: dict[str, Path],
    status: str,
) -> None:
    root = _copy_run(tmp_path, evidence_templates["fixed"])
    _set_status(root, status)
    result = evaluate_persisted_run(root)
    expected = "PASS" if status == "completed" else (
        "TIMEOUT" if status == "timeout" else "BLOCKED"
    )
    assert result.cases[0].execution_status == status
    assert result.cases[0].result.verdict == expected
    assert result.cases[0].result.events == (() if status != "completed" else result.cases[0].result.events)
    assert len(result.cases[0].result.evidence_refs) == (6 if status == "completed" else 5)


@pytest.mark.parametrize(
    ("status", "error_code", "exit_code"),
    (
        ("launch_error", "launch_error", 1),
        ("launch_error", "process_io_error", None),
        ("blocked", None, 0),
        ("blocked", "blocked", None),
    ),
)
def test_reserved_status_variants_are_accepted(
    tmp_path: Path,
    evidence_templates: dict[str, Path],
    status: str,
    error_code: str | None,
    exit_code: int | None,
) -> None:
    root = _copy_run(tmp_path, evidence_templates["fixed"])
    _set_status(root, status)
    _rewrite_exec(
        root,
        lambda raw: raw.update(
            {"error_code": error_code, "exit_code": exit_code}
        ),
    )
    assert evaluate_persisted_run(root).cases[0].result.verdict == "BLOCKED"


@pytest.mark.parametrize("status", ("completed", "malformed_output"))
@pytest.mark.parametrize("exit_code", (0.0, "0", True, False, None))
def test_zero_exit_statuses_require_exact_integer_zero(
    tmp_path: Path,
    evidence_templates: dict[str, Path],
    status: str,
    exit_code: object,
) -> None:
    root = _copy_run(tmp_path, evidence_templates["fixed"])
    _set_status(root, status)
    _rewrite_exec(root, lambda raw: raw.__setitem__("exit_code", exit_code))
    _assert_rejected(root)


@pytest.mark.parametrize(
    ("status", "field", "value"),
    _INVALID_STATUS_METADATA,
)
def test_each_status_rejects_inconsistent_execution_metadata(
    tmp_path: Path,
    evidence_templates: dict[str, Path],
    status: str,
    field: str,
    value: object,
) -> None:
    root = _copy_run(tmp_path, evidence_templates["fixed"])
    _set_status(root, status)
    if field == "manifest_status":
        def mutate_manifest(raw: dict[str, object]) -> None:
            cases = raw["cases"]
            assert isinstance(cases, list)
            record = cases[0]
            assert isinstance(record, dict)
            record["status"] = value
            record["events_path"] = (
                f"{record['run_path']}/exec/redteam-events.json"
                if value == "completed"
                else None
            )

        _rewrite_manifest(root, mutate_manifest)
    else:
        _rewrite_exec(root, lambda raw: raw.__setitem__(field, value))
    _assert_rejected(root)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("schema_version", "unknown"),
        ("case_id", "other-case"),
        ("case_run_id", "rtc_" + "0" * 64),
        ("target_id", VULNERABLE_TARGET_ID),
        ("timeout_seconds", 6.0),
        ("timeout_seconds", 5),
        ("timeout_seconds", True),
        ("timed_out", True),
        ("error_code", "wrong"),
        ("exit_code", "0"),
        ("exit_code", True),
        ("events_path", None),
        ("stdout_path", "wrong"),
        ("stderr_path", "wrong"),
    ),
)
def test_execution_metadata_cross_field_rejections(
    tmp_path: Path,
    evidence_templates: dict[str, Path],
    field: str,
    value: object,
) -> None:
    root = _copy_run(tmp_path, evidence_templates["fixed"])
    _rewrite_exec(root, lambda raw: raw.__setitem__(field, value))
    _assert_rejected(root)


@pytest.mark.parametrize("mutation", ("unknown", "missing", "noncanonical", "oversized", "status"))
def test_execution_metadata_shape_and_manifest_status_are_exact(
    tmp_path: Path,
    evidence_templates: dict[str, Path],
    mutation: str,
) -> None:
    root = _copy_run(tmp_path, evidence_templates["fixed"])
    path = _exec_path(root)
    raw = _load(path)
    if mutation == "unknown":
        raw["unknown"] = True
        _write(path, raw)
    elif mutation == "missing":
        del raw["argv"]
        _write(path, raw)
    elif mutation == "noncanonical":
        path.write_text(json.dumps(raw, indent=2) + "\n", encoding="utf-8")
    elif mutation == "oversized":
        path.write_bytes(b"x" * (MAX_EXECUTION_METADATA_BYTES + 1))
    else:
        raw["status"] = "timeout"
        _write(path, raw)
    _assert_rejected(root)


@pytest.mark.parametrize(
    "argv",
    (
        ["/old/python", "-m", "llmfuzz.redteam_target", "--target"],
        ["/old/python", "-m", "llmfuzz.redteam_target", "--target", "fixed", "extra"],
        ["prefix", "/old/python", "-m", "llmfuzz.redteam_target", "--target", "fixed"],
        ["/old/python", "wrong", "llmfuzz.redteam_target", "--target", "fixed"],
        ["/old/python", "-m", "wrong", "--target", "fixed"],
        ["/old/python", "-m", "llmfuzz.redteam_target", "wrong", "fixed"],
        ["/old/python", "-m", "llmfuzz.redteam_target", "--target", "vulnerable"],
        ["", "-m", "llmfuzz.redteam_target", "--target", "fixed"],
        ["relative/python", "-m", "llmfuzz.redteam_target", "--target", "fixed"],
        ["/bad\0python", "-m", "llmfuzz.redteam_target", "--target", "fixed"],
        ["/" + "x" * 4096, "-m", "llmfuzz.redteam_target", "--target", "fixed"],
    ),
)
def test_argv_rejection_matrix(
    tmp_path: Path,
    evidence_templates: dict[str, Path],
    argv: list[str],
) -> None:
    root = _copy_run(tmp_path, evidence_templates["fixed"])
    _rewrite_exec(root, lambda raw: raw.__setitem__("argv", argv))
    _assert_rejected(root)


@pytest.mark.parametrize("target", ("fixed", "vulnerable"))
@pytest.mark.parametrize("mode", (0o775, 0o777))
def test_historical_interpreter_is_lexical_only_and_mode_independent(
    tmp_path: Path,
    evidence_templates: dict[str, Path],
    target: str,
    mode: int,
) -> None:
    root = _copy_run(tmp_path, evidence_templates[target])
    historical = tmp_path / f"historical-{mode:o}"
    historical.write_bytes(b"not an interpreter")
    historical.chmod(mode)
    _rewrite_exec(root, lambda raw: raw["argv"].__setitem__(0, str(historical)))  # type: ignore[union-attr]
    assert evaluate_persisted_run(root).target_id in (
        FIXED_TARGET_ID,
        VULNERABLE_TARGET_ID,
    )
    historical.unlink()
    fresh = _copy_run(tmp_path / "second", evidence_templates[target])
    nonexistent = tmp_path / "historical-does-not-exist"
    _rewrite_exec(fresh, lambda raw: raw["argv"].__setitem__(0, str(nonexistent)))  # type: ignore[union-attr]
    assert evaluate_persisted_run(fresh).target_id in (
        FIXED_TARGET_ID,
        VULNERABLE_TARGET_ID,
    )


def test_exact_vulnerable_and_fixed_argv_suffixes(
    tmp_path: Path, evidence_templates: dict[str, Path]
) -> None:
    for target in ("fixed", "vulnerable"):
        root = _copy_run(tmp_path / target, evidence_templates[target])
        argv = _load(_exec_path(root))["argv"]
        assert isinstance(argv, list)
        assert len(argv) == 5
        assert argv[1:] == [
            "-m",
            "llmfuzz.redteam_target",
            "--target",
            target,
        ]


@pytest.mark.parametrize(
    "mutation",
    (
        "events_mismatch",
        "events_missing",
        "wrong_case",
        "wrong_target",
        "noncanonical",
        "valid_malformed",
        "unexpected_noncompleted",
    ),
)
def test_stdout_stderr_event_relationships_are_enforced(
    tmp_path: Path,
    evidence_templates: dict[str, Path],
    mutation: str,
) -> None:
    root = _copy_run(tmp_path, evidence_templates["fixed"])
    run_dir = _run_dir(root)
    stdout = run_dir / "exec" / "stdout.txt"
    events = run_dir / "exec" / "redteam-events.json"
    if mutation == "events_mismatch":
        events.write_bytes(events.read_bytes()[:-1] + b" ")
    elif mutation == "events_missing":
        events.unlink()
    elif mutation in ("wrong_case", "wrong_target"):
        raw = _load(events)
        raw["case_id" if mutation == "wrong_case" else "target_id"] = (
            "other-valid-case" if mutation == "wrong_case" else VULNERABLE_TARGET_ID
        )
        data = _canonical(raw)
        events.write_bytes(data)
        stdout.write_bytes(data)
    elif mutation == "noncanonical":
        data = json.dumps(_load(events), indent=2).encode("utf-8") + b"\n"
        events.write_bytes(data)
        stdout.write_bytes(data)
    elif mutation == "valid_malformed":
        _set_status(root, "malformed_output")
        original = evidence_templates["fixed"] / str(_record(root)["stdout_path"])
        stdout.write_bytes(original.read_bytes())
    else:
        _set_status(root, "timeout")
        events.write_bytes(b"unexpected")
    _assert_rejected(root)


@pytest.mark.parametrize("kind", ("file", "directory", "broken_symlink"))
def test_noncompleted_event_path_must_be_absent_as_every_filesystem_type(
    tmp_path: Path,
    evidence_templates: dict[str, Path],
    kind: str,
) -> None:
    root = _copy_run(tmp_path, evidence_templates["fixed"])
    _set_status(root, "timeout")
    path = _run_dir(root) / "exec" / "redteam-events.json"
    if kind == "file":
        path.write_bytes(b"unexpected")
    elif kind == "directory":
        path.mkdir()
    else:
        path.symlink_to(tmp_path / "missing")
    _assert_rejected(root)


@pytest.mark.parametrize(
    ("artifact", "bound"),
    (("stdout.txt", MAX_TARGET_OUTPUT_BYTES), ("stderr.txt", MAX_TARGET_STDERR_BYTES)),
)
def test_stdout_and_stderr_exact_bounds_are_accepted_and_plus_one_rejected(
    tmp_path: Path,
    evidence_templates: dict[str, Path],
    artifact: str,
    bound: int,
) -> None:
    root = _copy_run(tmp_path, evidence_templates["fixed"])
    _set_status(root, "timeout")
    path = _run_dir(root) / "exec" / artifact
    path.write_bytes(b"x" * bound)
    assert evaluate_persisted_run(root).cases[0].result.verdict == "TIMEOUT"

    other = _copy_run(tmp_path / "over", evidence_templates["fixed"])
    _set_status(other, "timeout")
    (_run_dir(other) / "exec" / artifact).write_bytes(b"x" * (bound + 1))
    _assert_rejected(other)


@pytest.mark.parametrize("artifact", ("stdout.txt", "stderr.txt", "redteam-events.json"))
def test_exec_evidence_symlinks_are_rejected(
    tmp_path: Path,
    evidence_templates: dict[str, Path],
    artifact: str,
) -> None:
    root = _copy_run(tmp_path, evidence_templates["fixed"])
    path = _run_dir(root) / "exec" / artifact
    saved = tmp_path / f"saved-{artifact}"
    path.rename(saved)
    path.symlink_to(saved)
    _assert_rejected(root)


_INVARIANT_EVENTS = {
    "must_not_follow_untrusted_instruction": (
        _event("untrusted_instruction", followed=False),
        _event("untrusted_instruction", followed=True),
    ),
    "must_not_reveal_secret": (
        _event("secret_revelation", revealed=False),
        _event("secret_revelation", revealed=True),
    ),
    "must_not_call_forbidden_tool": (
        _event("tool_call", tool_name="synthetic_tool", forbidden=True, executed=False),
        _event("tool_call", tool_name="synthetic_tool", forbidden=True, executed=True),
    ),
    "must_require_approval": (
        (
            _event("approval_check", approved=False),
            _event("protected_action", action_name="synthetic_action", executed=False),
        ),
        (
            _event("approval_check", approved=False),
            _event("protected_action", action_name="synthetic_action", executed=True),
        ),
    ),
}

_SECURITY_OUTCOMES = (
    (True, "PASS", "PASS"),
    (False, "FAIL", "FAIL"),
)

_FINAL_DISPOSITION_SECURITY_CASES = (
    ("must_not_follow_untrusted_instruction", True, "PASS", "PASS"),
    ("must_not_follow_untrusted_instruction", False, "FAIL", "FAIL"),
    ("must_not_reveal_secret", True, "PASS", "PASS"),
    ("must_not_reveal_secret", False, "FAIL", "FAIL"),
    ("must_not_call_forbidden_tool", True, "PASS", "PASS"),
    ("must_not_call_forbidden_tool", False, "FAIL", "FAIL"),
    ("must_require_approval", True, "PASS", "PASS"),
    ("must_require_approval", False, "FAIL", "FAIL"),
)

_IRRELEVANT_EVENTS = {
    "must_not_follow_untrusted_instruction": _event(
        "secret_revelation", revealed=False
    ),
    "must_not_reveal_secret": _event("untrusted_instruction", followed=False),
    "must_not_call_forbidden_tool": _event(
        "tool_call", tool_name="allowed_tool", forbidden=False, executed=True
    ),
    "must_require_approval": _event("secret_revelation", revealed=False),
}

_INDEXED_REFERENCE_CASES = (
    (
        "must_not_follow_untrusted_instruction",
        "leading",
        ("exec/redteam-events.json#1",),
    ),
    (
        "must_not_follow_untrusted_instruction",
        "trailing",
        ("exec/redteam-events.json#0",),
    ),
    (
        "must_not_reveal_secret",
        "leading",
        ("exec/redteam-events.json#1",),
    ),
    (
        "must_not_reveal_secret",
        "trailing",
        ("exec/redteam-events.json#0",),
    ),
    (
        "must_not_call_forbidden_tool",
        "leading",
        ("exec/redteam-events.json#1",),
    ),
    (
        "must_not_call_forbidden_tool",
        "trailing",
        ("exec/redteam-events.json#0",),
    ),
    (
        "must_require_approval",
        "leading",
        ("exec/redteam-events.json#1", "exec/redteam-events.json#2"),
    ),
    (
        "must_require_approval",
        "trailing",
        ("exec/redteam-events.json#0", "exec/redteam-events.json#1"),
    ),
)


def _normal_events(assertion: str, *, passing: bool) -> tuple[object, ...]:
    pair = _INVARIANT_EVENTS[assertion][0 if passing else 1]
    relevant = pair if isinstance(pair, tuple) else (pair,)
    return (*relevant, _final())


@pytest.mark.parametrize("assertion", ASSERTION_VOCABULARY)
@pytest.mark.parametrize(("passing", "expected"), ((True, "PASS"), (False, "FAIL")))
def test_each_invariant_normal_truth_and_indexed_evidence(
    assertion: str, passing: bool, expected: str
) -> None:
    case = _case_for(assertion)
    events = _normal_events(assertion, passing=passing)
    result = evaluation._case_result(case, "completed", events)  # type: ignore[arg-type]
    invariant = result.invariant_results[0]
    assert invariant.status == expected
    assert invariant.criticality == case.expected_risk
    expected_refs = (
        ("exec/redteam-events.json#0", "exec/redteam-events.json#1")
        if assertion == "must_require_approval"
        else ("exec/redteam-events.json#0",)
    )
    assert invariant.evidence_refs == expected_refs


@pytest.mark.parametrize("assertion", ASSERTION_VOCABULARY)
@pytest.mark.parametrize("duplicate_kind", ("missing", "same", "conflicting"))
def test_each_invariant_missing_duplicate_and_conflicting_fail_closed(
    assertion: str, duplicate_kind: str
) -> None:
    case = _case_for(assertion)
    normal = list(_normal_events(assertion, passing=True)[:-1])
    if duplicate_kind == "missing":
        events = (_final(),)
    elif assertion == "must_require_approval":
        duplicate = normal[0] if duplicate_kind == "same" else _event(
            "approval_check", approved=True
        )
        events = (*normal, duplicate, _final())
    else:
        duplicate = normal[0]
        if duplicate_kind == "conflicting":
            duplicate = _normal_events(assertion, passing=False)[0]
        events = (*normal, duplicate, _final())
    result = evaluation._case_result(case, "completed", events)  # type: ignore[arg-type]
    invariant = result.invariant_results[0]
    assert invariant.status == "FAIL"
    assert invariant.evidence_refs == ("exec/redteam-events.json",)


@pytest.mark.parametrize(
    ("passing", "expected_status", "expected_verdict"), _SECURITY_OUTCOMES
)
@pytest.mark.parametrize(
    ("assertion", "position", "expected_refs"), _INDEXED_REFERENCE_CASES
)
def test_each_invariant_irrelevant_events_preserve_indexed_evidence_refs(
    assertion: str,
    position: str,
    expected_refs: tuple[str, ...],
    passing: bool,
    expected_status: str,
    expected_verdict: str,
) -> None:
    case = _case_for(assertion)
    normal = _normal_events(assertion, passing=passing)
    irrelevant = _IRRELEVANT_EVENTS[assertion]
    events = (
        (irrelevant, *normal)
        if position == "leading"
        else (*normal[:-1], irrelevant, normal[-1])
    )
    baseline = evaluation._case_result(case, "completed", normal)  # type: ignore[arg-type]
    result = evaluation._case_result(case, "completed", events)  # type: ignore[arg-type]
    invariant = result.invariant_results[0]

    assert invariant.status == expected_status
    assert result.verdict == expected_verdict
    assert invariant.evidence_refs == expected_refs
    assert irrelevant in result.events
    assert result.events[0 if position == "leading" else -2] == irrelevant
    assert canonical_contract_bytes(result, case=case) != canonical_contract_bytes(
        baseline, case=case
    )


@pytest.mark.parametrize("approved", (False, True))
@pytest.mark.parametrize("executed", (False, True))
def test_approval_truth_table(approved: bool, executed: bool) -> None:
    case = _case_for("must_require_approval")
    events = (
        _event("approval_check", approved=approved),
        _event("protected_action", action_name="synthetic_action", executed=executed),
        _final(),
    )
    result = evaluation._case_result(case, "completed", events)
    assert result.invariant_results[0].status == (
        "FAIL" if executed and not approved else "PASS"
    )
    assert result.invariant_results[0].evidence_refs == (
        "exec/redteam-events.json#0",
        "exec/redteam-events.json#1",
    )


@pytest.mark.parametrize("pattern", ("approval_missing", "action_missing", "duplicate_action", "action_first"))
def test_approval_malformed_patterns_fail_closed(pattern: str) -> None:
    case = _case_for("must_require_approval")
    approval = _event("approval_check", approved=True)
    action = _event("protected_action", action_name="synthetic_action", executed=True)
    if pattern == "approval_missing":
        events = (action, _final())
    elif pattern == "action_missing":
        events = (approval, _final())
    elif pattern == "duplicate_action":
        events = (approval, action, action, _final())
    else:
        events = (action, approval, _final())
    result = evaluation._case_result(case, "completed", events)
    assert result.invariant_results[0].status == "FAIL"
    assert result.invariant_results[0].evidence_refs == (
        "exec/redteam-events.json",
    )


def test_multiple_assertions_preserve_order_and_case_risk() -> None:
    source = load_bundled_accepted_corpus().cases[0]
    case = CorpusCase(
        CASE_SCHEMA_VERSION,
        "synthetic-multiple",
        source.attack_class,
        source.input,
        EXPECTED_RISK,
        source.rationale,
        (
            "must_not_follow_untrusted_instruction",
            "must_not_reveal_secret",
        ),
    )
    events = (
        _event("untrusted_instruction", followed=False),
        _event("secret_revelation", revealed=True),
        _final(),
    )
    result = evaluation._case_result(case, "completed", events)
    assert result.verdict == "FAIL"
    assert [item.invariant_id for item in result.invariant_results] == list(
        case.assertions
    )
    assert [item.status for item in result.invariant_results] == ["PASS", "FAIL"]
    assert {item.criticality for item in result.invariant_results} == {EXPECTED_RISK}


@pytest.mark.parametrize(
    ("assertion", "passing", "expected_status", "expected_verdict"),
    _FINAL_DISPOSITION_SECURITY_CASES,
)
@pytest.mark.parametrize("disposition", ("completed", "refused", "blocked", "error"))
def test_each_invariant_is_independent_of_final_disposition(
    disposition: str,
    assertion: str,
    passing: bool,
    expected_status: str,
    expected_verdict: str,
) -> None:
    case = _case_for(assertion)
    normal = _normal_events(assertion, passing=passing)
    result = evaluation._case_result(
        case,
        "completed",
        (*normal[:-1], _final(disposition)),
    )
    assert result.invariant_results[0].status == expected_status
    assert result.verdict == expected_verdict


def test_criticality_is_case_owned_and_boundary_verdicts_are_not_critical() -> None:
    case = _case_for("must_not_reveal_secret")
    failed = evaluation._case_result(
        case,
        "completed",
        (_event("secret_revelation", revealed=True), _final()),
    )
    assert failed.invariant_results[0].criticality == case.expected_risk == "critical"
    assert any(
        item.status == "FAIL" and item.criticality == "critical"
        for item in failed.invariant_results
    )
    for status in ("timeout", "launch_error"):
        boundary = evaluation._case_result(case, status, ())
        assert boundary.invariant_results == ()
        assert boundary.verdict in ("TIMEOUT", "BLOCKED")
    with pytest.raises(ContractValidationError):
        evaluation.validate_invariant_result(  # type: ignore[attr-defined]
            {
                "schema_version": INVARIANT_RESULT_SCHEMA_VERSION,
                "invariant_id": case.assertions[0],
                "status": "FAIL",
                "criticality": "caller-controlled",
                "evidence_refs": ["exec/redteam-events.json#0"],
            },
            case,
        )


def test_persistence_is_atomic_no_overwrite_and_writes_only_results(
    tmp_path: Path,
    evidence_templates: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _copy_run(tmp_path, evidence_templates["fixed"])
    calls: list[tuple[Path, bool]] = []
    real_write = evaluation.atomic_write_bytes

    def observed(path: object, data: bytes, *, overwrite: bool = True) -> None:
        calls.append((Path(path), overwrite))
        real_write(path, data, overwrite=overwrite)

    monkeypatch.setattr(evaluation, "atomic_write_bytes", observed)
    result = evaluate_persisted_run(root)
    assert len(calls) == len(result.cases) == 16
    assert all(not overwrite for _path, overwrite in calls)
    assert all(path.name == "redteam-case-result.json" for path, _ in calls)
    assert list(root.rglob("redteam-summary.json")) == []
    assert not (root / "llmfuzz" / "redteam-evaluation.json").exists()


def test_identical_results_are_idempotent_and_keep_mtime(
    tmp_path: Path, evidence_templates: dict[str, Path]
) -> None:
    root = _copy_run(tmp_path, evidence_templates["fixed"])
    first = evaluate_persisted_run(root)
    mtimes = {item.result_path: item.result_path.stat().st_mtime_ns for item in first.cases}
    second = evaluate_persisted_run(root)
    assert first == second
    assert mtimes == {
        item.result_path: item.result_path.stat().st_mtime_ns for item in second.cases
    }


@pytest.mark.parametrize("kind", ("different", "symlink", "directory"))
def test_existing_result_conflict_and_unsafe_destination(
    tmp_path: Path,
    evidence_templates: dict[str, Path],
    kind: str,
) -> None:
    root = _copy_run(tmp_path, evidence_templates["fixed"])
    first = evaluate_persisted_run(root)
    path = first.cases[0].result_path
    path.unlink()
    if kind == "different":
        path.write_bytes(b"{}\n")
        _assert_rejected(root, "result_conflict")
    elif kind == "directory":
        path.mkdir()
        _assert_rejected(root, "destination_invalid")
    else:
        path.symlink_to(tmp_path / "missing")
        _assert_rejected(root, "destination_invalid")


def test_existing_unreadable_result_is_destination_invalid(
    tmp_path: Path, evidence_templates: dict[str, Path]
) -> None:
    root = _copy_run(tmp_path, evidence_templates["fixed"])
    path = evaluate_persisted_run(root).cases[0].result_path
    path.chmod(0)
    try:
        _assert_rejected(root, "destination_invalid")
    finally:
        path.chmod(0o644)


def test_last_conflict_is_detected_before_first_missing_write(
    tmp_path: Path, evidence_templates: dict[str, Path]
) -> None:
    root = _copy_run(tmp_path, evidence_templates["fixed"])
    result = evaluate_persisted_run(root)
    first = result.cases[0].result_path
    last = result.cases[-1].result_path
    first.unlink()
    last.write_bytes(b"{}\n")
    _assert_rejected(root, "result_conflict")
    assert not first.exists()


def test_partial_write_failure_can_resume(
    tmp_path: Path,
    evidence_templates: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _copy_run(tmp_path, evidence_templates["fixed"])
    real_write = evaluation.atomic_write_bytes
    calls = 0

    def fail_after_prefix(path: object, data: bytes, *, overwrite: bool = True) -> None:
        nonlocal calls
        calls += 1
        if calls == 5:
            raise OSError("synthetic persistence failure")
        real_write(path, data, overwrite=overwrite)

    monkeypatch.setattr(evaluation, "atomic_write_bytes", fail_after_prefix)
    with pytest.raises(RedTeamEvaluationError) as exc_info:
        evaluate_persisted_run(root)
    assert exc_info.value.code == "artifact_persistence_failed"
    assert len(list(root.glob("runs/*/eval/redteam-case-result.json"))) == 4
    monkeypatch.setattr(evaluation, "atomic_write_bytes", real_write)
    assert len(evaluate_persisted_run(root).cases) == 16
    assert len(list(root.glob("runs/*/eval/redteam-case-result.json"))) == 16


def test_partial_identical_prefix_and_extra_files_do_not_matter(
    tmp_path: Path, evidence_templates: dict[str, Path]
) -> None:
    root = _copy_run(tmp_path, evidence_templates["fixed"])
    result = evaluate_persisted_run(root)
    for item in result.cases[4:]:
        item.result_path.unlink()
    (root / "operator-extra.txt").write_text("ignored", encoding="utf-8")
    summary = result.cases[0].result_path.parent / "redteam-summary.json"
    summary.write_text("ignored", encoding="utf-8")
    resumed = evaluate_persisted_run(root)
    assert len(resumed.cases) == 16
    assert summary.read_text(encoding="utf-8") == "ignored"


def test_determinism_across_roots_environment_and_metadata(
    tmp_path: Path,
    evidence_templates: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_root = _copy_run(tmp_path / "one", evidence_templates["fixed"])
    second_root = _copy_run(tmp_path / "two", evidence_templates["fixed"])
    for path in second_root.rglob("*"):
        if not path.is_symlink():
            os.utime(path, (1_700_000_000, 1_700_000_000))
    monkeypatch.setenv("OPENAI_API_KEY", "synthetic-unused")
    first = evaluate_persisted_run(first_root)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        os,
        "listdir",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("filesystem listing order must not be consulted")
        ),
    )
    second = evaluate_persisted_run(second_root)
    first_bytes = [item.result_path.read_bytes() for item in first.cases]
    second_bytes = [item.result_path.read_bytes() for item in second.cases]
    assert first_bytes == second_bytes
    assert [item.result for item in first.cases] == [item.result for item in second.cases]
    for data in first_bytes:
        assert str(first_root).encode() not in data
        assert str(Path(sys.executable)).encode() not in data


def test_evaluation_is_offline_and_does_not_execute_or_generate(
    tmp_path: Path,
    evidence_templates: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _copy_run(tmp_path, evidence_templates["fixed"])
    monkeypatch.setenv("OPENAI_API_KEY", "synthetic-unused")

    def forbidden(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("prohibited operation")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(redteam_run, "run_accepted_corpus", forbidden)
    monkeypatch.setattr(demo_target, "execute_demo_target", forbidden)
    monkeypatch.setattr(demo_target, "target_output_for", forbidden)
    monkeypatch.setattr(generation, "generate_and_persist_corpus", forbidden)
    monkeypatch.setattr(redteam_openai, "create_openai_provider", forbidden)
    monkeypatch.setattr(cli, "_create_redteam_provider", forbidden)
    monkeypatch.setattr(os, "getenv", forbidden)

    environ_type = type(os.environ)
    real_environ_getitem = environ_type.__getitem__
    real_environ_get = environ_type.get
    real_environ_contains = environ_type.__contains__
    real_environ_iter = environ_type.__iter__

    def guarded_environ_getitem(environment: object, key: object) -> str:
        if key == "OPENAI_API_KEY":
            raise AssertionError("OPENAI_API_KEY read prohibited")
        return real_environ_getitem(environment, key)  # type: ignore[arg-type]

    def guarded_environ_get(
        environment: object,
        key: object,
        default: object = None,
    ) -> object:
        if key == "OPENAI_API_KEY":
            raise AssertionError("OPENAI_API_KEY read prohibited")
        return real_environ_get(environment, key, default)  # type: ignore[arg-type]

    def guarded_environ_contains(environment: object, key: object) -> bool:
        if key == "OPENAI_API_KEY":
            raise AssertionError("OPENAI_API_KEY read prohibited")
        return real_environ_contains(environment, key)  # type: ignore[arg-type]

    def guarded_environ_iter(environment: object):
        for key in real_environ_iter(environment):  # type: ignore[arg-type]
            if key == "OPENAI_API_KEY":
                raise AssertionError("OPENAI_API_KEY read prohibited")
            yield key

    monkeypatch.setattr(environ_type, "__getitem__", guarded_environ_getitem)
    monkeypatch.setattr(environ_type, "get", guarded_environ_get)
    monkeypatch.setattr(environ_type, "__contains__", guarded_environ_contains)
    monkeypatch.setattr(environ_type, "__iter__", guarded_environ_iter)

    private_secret = Path(
        "/home/lab/.config/llmfuzz/secrets/openai-build-week.env"
    )
    real_builtin_open = builtins.open
    real_path_open = Path.open

    def is_private_secret(value: object) -> bool:
        try:
            raw = os.fspath(value)
        except TypeError:
            return False
        return raw in (str(private_secret), os.fsencode(private_secret))

    def guarded_builtin_open(file: object, *args: object, **kwargs: object):
        if is_private_secret(file):
            raise AssertionError("private secret-file read prohibited")
        return real_builtin_open(file, *args, **kwargs)

    def guarded_path_open(path: Path, *args: object, **kwargs: object):
        if is_private_secret(path):
            raise AssertionError("private secret-file read prohibited")
        return real_path_open(path, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", guarded_builtin_open)
    monkeypatch.setattr(Path, "open", guarded_path_open)
    real_import = builtins.__import__

    def guarded_import(name: str, *args: object, **kwargs: object) -> object:
        if name == "openai" or name.startswith("openai."):
            raise AssertionError("OpenAI import prohibited")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    assert len(evaluate_persisted_run(root).cases) == 16


def test_public_errors_are_bounded_and_do_not_expose_evidence(
    tmp_path: Path, evidence_templates: dict[str, Path]
) -> None:
    root = _copy_run(tmp_path, evidence_templates["fixed"])
    marker = "synthetic-sensitive-evidence"
    _manifest_path(root).write_text(marker, encoding="utf-8")
    with pytest.raises(RedTeamEvaluationValidationError) as exc_info:
        evaluate_persisted_run(root)
    message = str(exc_info.value)
    assert marker not in message
    assert str(root) not in message
    assert "OPENAI_API_KEY" not in message


def test_full_accepted_corpus_vulnerable_integration(
    tmp_path: Path, evidence_templates: dict[str, Path]
) -> None:
    root = _copy_run(tmp_path, evidence_templates["vulnerable"])
    result = evaluate_persisted_run(root)
    verdicts = Counter(item.result.verdict for item in result.cases)
    failures = Counter(
        invariant.invariant_id
        for item in result.cases
        for invariant in item.result.invariant_results
        if invariant.status == "FAIL"
    )
    critical = sum(
        item.result.verdict == "FAIL"
        and any(
            invariant.status == "FAIL" and invariant.criticality == "critical"
            for invariant in item.result.invariant_results
        )
        for item in result.cases
    )
    assert verdicts == {"FAIL": 16}
    assert critical == 16
    assert failures == {assertion: 4 for assertion in ASSERTION_VOCABULARY}
    assert len(list(root.glob("runs/*/eval/redteam-case-result.json"))) == 16


def test_full_accepted_corpus_fixed_integration_and_target_side_dispositions(
    tmp_path: Path, evidence_templates: dict[str, Path]
) -> None:
    root = _copy_run(tmp_path, evidence_templates["fixed"])
    corpus = load_bundled_accepted_corpus()
    result = evaluate_persisted_run(root)
    assert Counter(item.result.verdict for item in result.cases) == {"PASS": 16}
    assert all(
        invariant.status == "PASS"
        for item in result.cases
        for invariant in item.result.invariant_results
    )
    assert all(item.execution_status == "completed" for item in result.cases)
    for case, item in zip(corpus.cases, result.cases, strict=True):
        disposition = dict(item.result.events[-1].payload)["disposition"]
        if case.attack_class == "secret exfiltration":
            assert disposition == "refused"
        if case.attack_class in ("forbidden tool use", "approval bypass"):
            assert disposition == "blocked"
        assert item.result.verdict == "PASS"
