from __future__ import annotations

import builtins
import inspect
import json
import os
import shutil
import socket
import subprocess
import sys
from collections import Counter
from dataclasses import FrozenInstanceError, fields, replace
from pathlib import Path

import pytest

import llmfuzz.cli as cli
import llmfuzz.redteam_demo_target as demo_target
import llmfuzz.redteam_evaluation as evaluation
import llmfuzz.redteam_generation as generation
import llmfuzz.redteam_openai as redteam_openai
import llmfuzz.redteam_reporting as reporting
import llmfuzz.redteam_run as redteam_run
from llmfuzz.redteam_contracts import (
    CASE_RESULT_SCHEMA_VERSION,
    EVENT_SCHEMA_VERSION,
    INVARIANT_RESULT_SCHEMA_VERSION,
    CASE_VERDICTS,
    CaseResult,
    InvariantResult,
    ObservedEvent,
)
from llmfuzz.redteam_corpus import (
    ACCEPTED_CORPUS_SHA256,
    ASSERTION_VOCABULARY,
    ATTACK_CLASSES,
)
from llmfuzz.redteam_demo_target import FIXED_TARGET_ID, VULNERABLE_TARGET_ID
from llmfuzz.redteam_evaluation import (
    EvaluatedCase,
    RedTeamEvaluationError,
    RedTeamEvaluationResult,
    RedTeamEvaluationValidationError,
    evaluate_persisted_run,
)
from llmfuzz.redteam_reporting import (
    COMPARISON_MARKDOWN_RELATIVE_PATH,
    COMPARISON_RELATIVE_PATH,
    COMPARISON_SCHEMA_VERSION,
    EXPECTED_REPORT_CASES,
    FIXED_REPORT_RELATIVE_PATH,
    MAX_COMPARISON_REPORT_BYTES,
    MAX_MARKDOWN_REPORT_BYTES,
    MAX_REPORT_CLUSTERS,
    MAX_REPORT_PATH_CHARS,
    MAX_RUN_REPORT_BYTES,
    RUN_REPORT_RELATIVE_PATH,
    RUN_REPORT_SCHEMA_VERSION,
    SIGNATURE_ID_LENGTH,
    SIGNATURE_PREFIX,
    SIGNATURE_SCHEMA_VERSION,
    VULNERABLE_REPORT_RELATIVE_PATH,
    RedTeamComparisonResult,
    RedTeamReportingError,
    RedTeamReportingValidationError,
    RedTeamRunReportResult,
    compare_persisted_runs,
    report_persisted_run,
)
from llmfuzz.redteam_run import (
    ACCEPTED_PERSISTED_SHA256,
    EXECUTION_STATUSES,
    run_accepted_corpus,
)


_REPOSITORY = Path(__file__).resolve().parents[1]
_PRIVATE_SECRET_PATH = Path(
    "/home/lab/.config/llmfuzz/secrets/openai-build-week.env"
)
_EXPECTED_ACCEPTED_SIGNATURES = {
    "prompt injection": (
        "rtsig_28b01a166e700444998b01d48734697f28a5e28e478844e228a73ea85020b792"
    ),
    "secret exfiltration": (
        "rtsig_336412a21180d99d19e1ddc3bb4d036e978fe865fd3bd0e8836a13a63f2b6161"
    ),
    "forbidden tool use": (
        "rtsig_15da89533f1c1fa2342a51e75145e872f2fd8234bac939770b635b99fbc5e994"
    ),
    "approval bypass": (
        "rtsig_f3b7cd895690c1ad2386016b0aa4445c8955f7f7921c03ca9eea5df2788c4222"
    ),
}


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


def _load(path: Path) -> dict[str, object]:
    value = json.loads(path.read_bytes())
    assert isinstance(value, dict)
    return value


def _write(path: Path, value: object) -> None:
    path.write_bytes(_canonical(value))


@pytest.fixture(scope="module")
def run_templates(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    root = tmp_path_factory.mktemp("d3-source-runs")
    templates: dict[str, Path] = {}
    for target in ("vulnerable", "fixed"):
        path = root / target
        result = run_accepted_corpus(target=target, output=path)
        assert result.completed is True
        templates[target] = path
    return templates


@pytest.fixture(scope="module")
def evaluated_templates(
    tmp_path_factory: pytest.TempPathFactory,
    run_templates: dict[str, Path],
) -> dict[str, RedTeamEvaluationResult]:
    root = tmp_path_factory.mktemp("d3-evaluated-runs")
    results: dict[str, RedTeamEvaluationResult] = {}
    for target, template in run_templates.items():
        path = root / target
        shutil.copytree(template, path)
        results[target] = evaluate_persisted_run(path)
    return results


def _copy_run(tmp_path: Path, template: Path, name: str = "run") -> Path:
    root = tmp_path / name
    shutil.copytree(template, root)
    return root


def _manifest(root: Path) -> dict[str, object]:
    return _load(root / "llmfuzz" / "redteam-run.json")


def _record(root: Path, index: int) -> dict[str, object]:
    records = _manifest(root)["cases"]
    assert isinstance(records, list)
    record = records[index]
    assert isinstance(record, dict)
    return record


_STATUS_VALUES = {
    "completed": (None, 0, "exec/redteam-events.json"),
    "timeout": ("timeout", -15, None),
    "stdout_limit": ("stdout_limit", -15, None),
    "stderr_limit": ("stderr_limit", -15, None),
    "nonzero_exit": ("nonzero_exit", 7, None),
    "launch_error": ("process_io_error", None, None),
    "malformed_output": ("target_output_invalid", 0, None),
    "blocked": ("blocked", None, None),
}


def _set_status(root: Path, index: int, status: str) -> None:
    manifest = _manifest(root)
    records = manifest["cases"]
    assert isinstance(records, list)
    record = records[index]
    assert isinstance(record, dict)
    record["status"] = status
    record["events_path"] = (
        f"{record['run_path']}/exec/redteam-events.json"
        if status == "completed"
        else None
    )
    _write(root / "llmfuzz" / "redteam-run.json", manifest)

    run_dir = root / str(record["run_path"])
    execution_path = run_dir / "exec" / "exec.json"
    execution = _load(execution_path)
    error_code, exit_code, events_path = _STATUS_VALUES[status]
    execution.update(
        {
            "status": status,
            "error_code": error_code,
            "exit_code": exit_code,
            "events_path": events_path,
            "timed_out": status == "timeout",
            "stdout_limit_exceeded": status == "stdout_limit",
            "stderr_limit_exceeded": status == "stderr_limit",
        }
    )
    _write(execution_path, execution)
    events = run_dir / "exec" / "redteam-events.json"
    if status != "completed" and os.path.lexists(events):
        events.unlink()
    if status == "malformed_output":
        (run_dir / "exec" / "stdout.txt").write_bytes(b"invalid-json\n")


def _final(disposition: str = "completed") -> ObservedEvent:
    return ObservedEvent(
        EVENT_SCHEMA_VERSION,
        "final",
        (("disposition", disposition),),
    )


def _synthetic_item(
    *,
    case_id: str = "case-a",
    case_run_id: str = "rtc_case_a",
    attack_class: str = "prompt injection",
    verdict: str = "FAIL",
    execution_status: str = "completed",
    invariant_ids: tuple[str, ...] = ("must_not_follow_untrusted_instruction",),
    invariant_statuses: tuple[str, ...] = ("FAIL",),
    criticalities: tuple[str, ...] = ("critical",),
    invariant_refs: tuple[tuple[str, ...], ...] = (("exec/redteam-events.json#0",),),
    execution_error_code: str | None = None,
    disposition: str = "completed",
) -> EvaluatedCase:
    invariants = tuple(
        InvariantResult(
            INVARIANT_RESULT_SCHEMA_VERSION,
            invariant_id,
            status,
            criticality,
            refs,
        )
        for invariant_id, status, criticality, refs in zip(
            invariant_ids,
            invariant_statuses,
            criticalities,
            invariant_refs,
            strict=True,
        )
    )
    completed = verdict in ("PASS", "FAIL")
    evidence = (
        "llmfuzz/redteam-corpus-reference.json",
        "input/redteam-target-input.json",
        "exec/exec.json",
        "exec/stdout.txt",
        "exec/stderr.txt",
        *(("exec/redteam-events.json",) if completed else ()),
    )
    result = CaseResult(
        CASE_RESULT_SCHEMA_VERSION,
        case_id,
        attack_class,
        (_final(disposition),) if completed else (),
        invariants if completed else (),
        evidence,
        verdict,
    )
    return EvaluatedCase(
        case_id,
        case_run_id,
        execution_status,
        execution_error_code,
        Path("/source") / "runs" / case_run_id / "eval" / "redteam-case-result.json",
        result,
    )


def _synthetic_evaluation(
    items: tuple[EvaluatedCase, ...],
    *,
    target_id: str = VULNERABLE_TARGET_ID,
    root: Path = Path("/source"),
    execution_id: str = "rt_synthetic",
) -> RedTeamEvaluationResult:
    return RedTeamEvaluationResult(
        root,
        execution_id,
        target_id,
        ACCEPTED_CORPUS_SHA256,
        ACCEPTED_PERSISTED_SHA256,
        items,
    )


def _actual_report_cli(*arguments: str) -> subprocess.CompletedProcess[bytes]:
    environment = os.environ.copy()
    environment.pop("OPENAI_API_KEY", None)
    environment["PYTHONPATH"] = str(_REPOSITORY)
    return subprocess.run(
        [sys.executable, "-m", "llmfuzz", "redteam", "report", *arguments],
        cwd=_REPOSITORY,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        shell=False,
    )


def test_public_literals_apis_models_and_errors_are_locked(tmp_path: Path) -> None:
    assert SIGNATURE_SCHEMA_VERSION == "llmfuzz.redteam.signature.v1"
    assert RUN_REPORT_SCHEMA_VERSION == "llmfuzz.redteam.report.v1"
    assert COMPARISON_SCHEMA_VERSION == "llmfuzz.redteam.comparison.v1"
    assert VULNERABLE_TARGET_ID == "llmfuzz.redteam.demo-target.vulnerable.v1"
    assert FIXED_TARGET_ID == "llmfuzz.redteam.demo-target.fixed.v1"
    assert CASE_VERDICTS == ("PASS", "FAIL", "TIMEOUT", "BLOCKED")
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
    assert EXPECTED_REPORT_CASES == 16
    assert MAX_REPORT_CLUSTERS == 16
    assert MAX_REPORT_PATH_CHARS == 4_096
    assert MAX_RUN_REPORT_BYTES == 262_144
    assert MAX_COMPARISON_REPORT_BYTES == 524_288
    assert MAX_MARKDOWN_REPORT_BYTES == 262_144
    assert SIGNATURE_PREFIX == "rtsig_"
    assert SIGNATURE_ID_LENGTH == 70
    assert RUN_REPORT_RELATIVE_PATH == "llmfuzz/redteam-report.json"
    assert VULNERABLE_REPORT_RELATIVE_PATH == "llmfuzz/redteam-vulnerable-report.json"
    assert FIXED_REPORT_RELATIVE_PATH == "llmfuzz/redteam-fixed-report.json"
    assert COMPARISON_RELATIVE_PATH == "llmfuzz/redteam-comparison.json"
    assert COMPARISON_MARKDOWN_RELATIVE_PATH == "llmfuzz/redteam-comparison.md"
    assert list(inspect.signature(report_persisted_run).parameters) == [
        "run_root",
        "output_root",
    ]
    assert list(inspect.signature(compare_persisted_runs).parameters) == [
        "vulnerable_run_root",
        "fixed_run_root",
        "output_root",
    ]
    assert [field.name for field in fields(RedTeamRunReportResult)] == [
        "output_root",
        "report_path",
        "execution_id",
        "target_id",
        "corpus_sha256",
        "persisted_sha256",
        "case_count",
        "verdict_counts",
        "critical_failure_count",
        "cluster_count",
    ]
    assert [field.name for field in fields(RedTeamComparisonResult)] == [
        "output_root",
        "vulnerable_report_path",
        "fixed_report_path",
        "comparison_path",
        "markdown_path",
        "corpus_sha256",
        "persisted_sha256",
        "case_count",
        "vulnerable_critical_failure_count",
        "fixed_critical_failure_count",
        "critical_failures_resolved",
        "critical_failures_introduced",
    ]
    frozen = RedTeamRunReportResult(
        tmp_path,
        tmp_path / "report",
        "execution",
        FIXED_TARGET_ID,
        ACCEPTED_CORPUS_SHA256,
        ACCEPTED_PERSISTED_SHA256,
        16,
        (("PASS", 16), ("FAIL", 0), ("TIMEOUT", 0), ("BLOCKED", 0)),
        0,
        0,
    )
    with pytest.raises(FrozenInstanceError):
        frozen.case_count = 0  # type: ignore[misc]


@pytest.mark.parametrize(
    ("error_type", "code", "normalized", "message"),
    (
        (RedTeamReportingValidationError, "run_rejected", "run_rejected", "Red Team report input validation failed."),
        (RedTeamReportingValidationError, "comparison_rejected", "comparison_rejected", "Red Team report comparison inputs do not match."),
        (RedTeamReportingValidationError, "destination_invalid", "destination_invalid", "Red Team report destination is invalid."),
        (RedTeamReportingValidationError, "artifact_conflict", "artifact_conflict", "Existing Red Team report conflicts with deterministic output."),
        (RedTeamReportingValidationError, "unknown", "run_rejected", "Red Team report input validation failed."),
        (RedTeamReportingError, "evaluation_failed", "evaluation_failed", "Red Team report evaluation failed."),
        (RedTeamReportingError, "artifact_persistence_failed", "artifact_persistence_failed", "Red Team report persistence failed."),
        (RedTeamReportingError, "reporting_internal_error", "reporting_internal_error", "Red Team reporting failed."),
        (RedTeamReportingError, "unknown", "reporting_internal_error", "Red Team reporting failed."),
    ),
)
def test_error_codes_messages_and_normalization(
    error_type: type[Exception],
    code: str,
    normalized: str,
    message: str,
) -> None:
    error = error_type(code)  # type: ignore[call-arg]
    assert error.code == normalized  # type: ignore[attr-defined]
    assert str(error) == message
    if error_type is RedTeamReportingValidationError:
        assert isinstance(error, ValueError)
    else:
        assert isinstance(error, RuntimeError)


def test_single_and_comparison_call_d2_exactly_once_per_run(
    tmp_path: Path,
    run_templates: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vulnerable = _copy_run(tmp_path, run_templates["vulnerable"], "vulnerable")
    fixed = _copy_run(tmp_path, run_templates["fixed"], "fixed")
    real_evaluate = reporting.evaluate_persisted_run
    calls: list[Path] = []

    def observed(root: object) -> RedTeamEvaluationResult:
        calls.append(Path(root))
        return real_evaluate(root)

    monkeypatch.setattr(reporting, "evaluate_persisted_run", observed)
    report_persisted_run(vulnerable, tmp_path / "single")
    assert calls == [vulnerable]
    calls.clear()
    compare_persisted_runs(vulnerable, fixed, tmp_path / "comparison")
    assert calls == [vulnerable, fixed]


@pytest.mark.parametrize(
    ("upstream_error", "expected_type", "expected_code"),
    (
        (
            RedTeamEvaluationValidationError("result_conflict"),
            RedTeamReportingValidationError,
            "run_rejected",
        ),
        (
            RedTeamEvaluationError("artifact_persistence_failed"),
            RedTeamReportingError,
            "evaluation_failed",
        ),
        (RuntimeError("private nested detail"), RedTeamReportingError, "evaluation_failed"),
    ),
)
def test_d2_errors_are_sanitized(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    upstream_error: Exception,
    expected_type: type[Exception],
    expected_code: str,
) -> None:
    def fail(_root: object) -> RedTeamEvaluationResult:
        raise upstream_error

    monkeypatch.setattr(reporting, "evaluate_persisted_run", fail)
    with pytest.raises(expected_type) as exc_info:
        report_persisted_run(tmp_path / "source", tmp_path / "output")
    assert exc_info.value.code == expected_code  # type: ignore[attr-defined]
    assert "private nested detail" not in str(exc_info.value)
    assert str(tmp_path) not in str(exc_info.value)


def test_missing_and_identical_d2_results_are_supported_and_summary_ignored(
    tmp_path: Path,
    run_templates: dict[str, Path],
) -> None:
    root = _copy_run(tmp_path, run_templates["fixed"])
    assert list(root.glob("runs/*/eval/redteam-case-result.json")) == []
    first = report_persisted_run(root, tmp_path / "first-report")
    assert len(list(root.glob("runs/*/eval/redteam-case-result.json"))) == 16
    summary = root / "runs" / next((root / "runs").iterdir()).name / "eval" / "redteam-summary.json"
    summary.write_text("ignored", encoding="utf-8")
    second = report_persisted_run(root, tmp_path / "second-report")
    assert first.case_count == second.case_count == 16
    assert first.report_path.read_bytes() == second.report_path.read_bytes()
    assert summary.read_text(encoding="utf-8") == "ignored"


def test_conflicting_d2_result_is_report_run_rejected(
    tmp_path: Path,
    run_templates: dict[str, Path],
) -> None:
    root = _copy_run(tmp_path, run_templates["fixed"])
    evaluated = evaluate_persisted_run(root)
    evaluated.cases[-1].result_path.write_bytes(b"{}\n")
    with pytest.raises(RedTeamReportingValidationError) as exc_info:
        report_persisted_run(root, tmp_path / "report")
    assert exc_info.value.code == "run_rejected"
    assert not (tmp_path / "report").exists()


@pytest.mark.parametrize(
    ("target", "expected_counts", "critical", "clusters"),
    (
        ("vulnerable", {"PASS": 0, "FAIL": 16, "TIMEOUT": 0, "BLOCKED": 0}, 16, 4),
        ("fixed", {"PASS": 16, "FAIL": 0, "TIMEOUT": 0, "BLOCKED": 0}, 0, 0),
    ),
)
def test_single_run_accepted_aggregation_and_exact_schema(
    tmp_path: Path,
    run_templates: dict[str, Path],
    target: str,
    expected_counts: dict[str, int],
    critical: int,
    clusters: int,
) -> None:
    root = _copy_run(tmp_path, run_templates[target])
    result = report_persisted_run(root, tmp_path / "report")
    report = _load(result.report_path)
    assert result.output_root.is_absolute()
    assert result.report_path.is_absolute()
    assert dict(result.verdict_counts) == expected_counts
    assert result.critical_failure_count == critical
    assert result.cluster_count == clusters
    assert set(report) == {
        "schema_version",
        "signature_schema_version",
        "case_result_schema_version",
        "corpus_sha256",
        "persisted_sha256",
        "execution_id",
        "target_id",
        "case_count",
        "verdict_counts",
        "critical_failure_count",
        "failed_invariant_counts",
        "attack_class_breakdown",
        "cases",
        "clusters",
    }
    assert report["schema_version"] == RUN_REPORT_SCHEMA_VERSION
    assert report["signature_schema_version"] == SIGNATURE_SCHEMA_VERSION
    assert report["case_result_schema_version"] == CASE_RESULT_SCHEMA_VERSION
    assert report["case_count"] == len(report["cases"]) == 16
    assert report["verdict_counts"] == expected_counts
    assert sum(report["verdict_counts"].values()) == 16
    assert [item["attack_class"] for item in report["attack_class_breakdown"]] == list(
        ATTACK_CLASSES
    )
    assert sum(item["case_count"] for item in report["attack_class_breakdown"]) == 16
    assert all(not str(ref).startswith("/") for case in report["cases"] for ref in case["evidence_refs"])
    assert str(root).encode() not in result.report_path.read_bytes()


@pytest.mark.parametrize(
    ("status", "verdict"),
    (
        ("timeout", "TIMEOUT"),
        ("stdout_limit", "BLOCKED"),
        ("stderr_limit", "BLOCKED"),
        ("nonzero_exit", "BLOCKED"),
        ("launch_error", "BLOCKED"),
        ("malformed_output", "BLOCKED"),
        ("blocked", "BLOCKED"),
    ),
)
def test_boundary_status_aggregation_and_signing(
    tmp_path: Path,
    run_templates: dict[str, Path],
    status: str,
    verdict: str,
) -> None:
    root = _copy_run(tmp_path, run_templates["fixed"])
    for index in range(16):
        _set_status(root, index, status)
    result = report_persisted_run(root, tmp_path / "report")
    report = _load(result.report_path)
    assert report["verdict_counts"][verdict] == 16
    assert report["critical_failure_count"] == 0
    assert all(case["verdict"] == verdict for case in report["cases"])
    assert all(case["signature_id"] is not None for case in report["cases"])
    assert all(case["invariants"] == [] for case in report["cases"])
    assert all(len(case["evidence_refs"]) == 5 for case in report["cases"])


def test_mixed_aggregation_counts_cases_and_failed_invariants() -> None:
    items = [
        _synthetic_item(case_id="a", case_run_id="r-a", verdict="PASS", invariant_statuses=("PASS",)),
        _synthetic_item(case_id="b", case_run_id="r-b"),
        _synthetic_item(case_id="c", case_run_id="r-c", verdict="TIMEOUT", execution_status="timeout"),
        _synthetic_item(case_id="d", case_run_id="r-d", verdict="BLOCKED", execution_status="launch_error"),
        _synthetic_item(
            case_id="e",
            case_run_id="r-e",
            invariant_ids=(
                "must_not_follow_untrusted_instruction",
                "must_not_reveal_secret",
            ),
            invariant_statuses=("FAIL", "FAIL"),
            criticalities=("critical", "critical"),
            invariant_refs=(("exec/redteam-events.json#0",), ("exec/redteam-events.json#1",)),
        ),
        _synthetic_item(
            case_id="f",
            case_run_id="r-f",
            invariant_ids=("must_not_follow_untrusted_instruction",),
            invariant_statuses=("FAIL",),
            criticalities=("noncritical",),
        ),
    ]
    result = RedTeamEvaluationResult(
        Path("/source"),
        "execution",
        VULNERABLE_TARGET_ID,
        ACCEPTED_CORPUS_SHA256,
        ACCEPTED_PERSISTED_SHA256,
        tuple(items),
    )
    report = reporting._build_run_report(result)
    assert report["verdict_counts"] == {"PASS": 1, "FAIL": 3, "TIMEOUT": 1, "BLOCKED": 1}
    assert report["critical_failure_count"] == 2
    assert report["failed_invariant_counts"] == {
        "must_not_follow_untrusted_instruction": 3,
        "must_not_reveal_secret": 1,
        "must_not_call_forbidden_tool": 0,
        "must_require_approval": 0,
    }


def test_signature_known_payload_and_accepted_literals(
    tmp_path: Path,
    run_templates: dict[str, Path],
) -> None:
    payload = {
        "schema_version": "llmfuzz.redteam.signature.v1",
        "attack_class": "prompt injection",
        "verdict": "FAIL",
        "execution_status": "completed",
        "failed_invariants": [
            {
                "invariant_id": "must_not_follow_untrusted_instruction",
                "evidence_scope": "indexed",
            }
        ],
    }
    expected_bytes = (
        b'{"attack_class":"prompt injection","execution_status":"completed",'
        b'"failed_invariants":[{"evidence_scope":"indexed","invariant_id":'
        b'"must_not_follow_untrusted_instruction"}],"schema_version":'
        b'"llmfuzz.redteam.signature.v1","verdict":"FAIL"}\n'
    )
    assert reporting._canonical_json_bytes(payload) == expected_bytes
    assert reporting._signature_id(payload) == _EXPECTED_ACCEPTED_SIGNATURES["prompt injection"]

    root = _copy_run(tmp_path, run_templates["vulnerable"])
    report = _load(report_persisted_run(root, tmp_path / "report").report_path)
    observed = {cluster["attack_class"]: cluster["signature_id"] for cluster in report["clusters"]}
    assert observed == _EXPECTED_ACCEPTED_SIGNATURES
    assert all(len(value) == 70 and value.startswith("rtsig_") for value in observed.values())


@pytest.mark.parametrize("invariant_id", ASSERTION_VOCABULARY)
def test_indexed_and_stream_signatures_are_stable_and_distinct(invariant_id: str) -> None:
    indexed = _synthetic_item(
        invariant_ids=(invariant_id,),
        invariant_refs=(("exec/redteam-events.json#0",),),
    )
    stream = replace(
        indexed,
        result=replace(
            indexed.result,
            invariant_results=(
                replace(indexed.result.invariant_results[0], evidence_refs=("exec/redteam-events.json",)),
            ),
        ),
    )
    indexed_payload = reporting._signature_payload(indexed)
    stream_payload = reporting._signature_payload(stream)
    assert indexed_payload["failed_invariants"] == [
        {"invariant_id": invariant_id, "evidence_scope": "indexed"}
    ]
    assert stream_payload["failed_invariants"] == [
        {"invariant_id": invariant_id, "evidence_scope": "stream"}
    ]
    assert reporting._signature_id(indexed_payload) != reporting._signature_id(stream_payload)


@pytest.mark.parametrize(
    ("left_status", "right_status"),
    (
        ("timeout", "stdout_limit"),
        ("stdout_limit", "stderr_limit"),
        ("nonzero_exit", "launch_error"),
        ("launch_error", "malformed_output"),
        ("malformed_output", "blocked"),
    ),
)
def test_boundary_execution_statuses_produce_distinct_signatures(
    left_status: str,
    right_status: str,
) -> None:
    left_verdict = "TIMEOUT" if left_status == "timeout" else "BLOCKED"
    right_verdict = "TIMEOUT" if right_status == "timeout" else "BLOCKED"
    left = _synthetic_item(verdict=left_verdict, execution_status=left_status)
    right = _synthetic_item(verdict=right_verdict, execution_status=right_status)
    assert reporting._signature_id(reporting._signature_payload(left)) != reporting._signature_id(
        reporting._signature_payload(right)
    )


def test_signature_excludes_case_run_target_execution_root_criticality_error_and_final() -> None:
    base = _synthetic_item()
    variants = (
        replace(base, case_id="different", result=replace(base.result, case_id="different")),
        replace(base, case_run_id="different-run"),
        replace(base, execution_error_code="different-error"),
        replace(base, result=replace(base.result, events=(_final("error"),))),
        replace(
            base,
            result=replace(
                base.result,
                invariant_results=(replace(base.result.invariant_results[0], criticality="other"),),
            ),
        ),
    )
    expected = reporting._signature_id(reporting._signature_payload(base))
    assert all(
        reporting._signature_id(reporting._signature_payload(variant)) == expected
        for variant in variants
    )
    assert reporting._signature_payload(
        _synthetic_item(verdict="PASS", invariant_statuses=("PASS",))
    ) is None


def test_signature_included_fields_change_identity_and_report_context_does_not() -> None:
    base = _synthetic_item()
    changed_attack = _synthetic_item(attack_class="secret exfiltration")
    changed_invariant = _synthetic_item(
        invariant_ids=("must_not_reveal_secret",),
    )
    base_id = reporting._signature_id(reporting._signature_payload(base))
    assert reporting._signature_id(reporting._signature_payload(changed_attack)) != base_id
    assert reporting._signature_id(reporting._signature_payload(changed_invariant)) != base_id
    first = reporting._build_run_report(
        _synthetic_evaluation((base,), root=Path("/one"), execution_id="first")
    )
    second = reporting._build_run_report(
        _synthetic_evaluation(
            (replace(base, result_path=Path("/different/result")),),
            root=Path("/two"),
            execution_id="second",
        )
    )
    assert first["cases"][0]["signature_id"] == second["cases"][0]["signature_id"]


def test_clusters_group_by_signature_preserve_case_order_and_choose_lexical_representative() -> None:
    items = (
        _synthetic_item(case_id="case-z", case_run_id="run-z"),
        _synthetic_item(case_id="case-a", case_run_id="run-a"),
        _synthetic_item(
            case_id="case-pass",
            case_run_id="run-pass",
            verdict="PASS",
            invariant_statuses=("PASS",),
        ),
    )
    report = reporting._build_run_report(_synthetic_evaluation(items))
    assert len(report["clusters"]) == 1
    cluster = report["clusters"][0]
    assert cluster["case_ids"] == ["case-z", "case-a"]
    assert cluster["representative_case_id"] == "case-a"
    assert cluster["representative_result_ref"] == (
        "runs/run-a/eval/redteam-case-result.json"
    )
    assert cluster["representative_evidence_refs"] == [
        "runs/run-a/exec/redteam-events.json#0"
    ]
    assert cluster["critical_failure_count"] == 2
    assert all("case-pass" not in entry["case_ids"] for entry in report["clusters"])
    reordered = reporting._build_run_report(
        _synthetic_evaluation((items[1], items[0], items[2]))
    )["clusters"][0]
    assert reordered["representative_case_id"] == "case-a"


def test_fail_representative_evidence_orders_invariants_and_deduplicates() -> None:
    item = _synthetic_item(
        invariant_ids=(
            "must_not_follow_untrusted_instruction",
            "must_not_reveal_secret",
        ),
        invariant_statuses=("FAIL", "FAIL"),
        criticalities=("critical", "critical"),
        invariant_refs=(
            ("exec/redteam-events.json", "exec/redteam-events.json#0"),
            ("exec/redteam-events.json", "exec/redteam-events.json#1"),
        ),
    )
    cluster = reporting._build_run_report(_synthetic_evaluation((item,)))["clusters"][0]
    assert cluster["failed_invariants"] == [
        {
            "invariant_id": "must_not_follow_untrusted_instruction",
            "evidence_scope": "stream",
        },
        {"invariant_id": "must_not_reveal_secret", "evidence_scope": "stream"},
    ]
    assert cluster["representative_evidence_refs"] == [
        "runs/rtc_case_a/exec/redteam-events.json",
        "runs/rtc_case_a/exec/redteam-events.json#0",
        "runs/rtc_case_a/exec/redteam-events.json#1",
    ]


@pytest.mark.parametrize(
    ("verdict", "status"),
    (("TIMEOUT", "timeout"), ("BLOCKED", "stdout_limit")),
)
def test_boundary_cluster_representative_evidence_is_fixed(
    verdict: str,
    status: str,
) -> None:
    item = _synthetic_item(verdict=verdict, execution_status=status)
    cluster = reporting._build_run_report(_synthetic_evaluation((item,)))["clusters"][0]
    assert cluster["representative_evidence_refs"] == [
        "runs/rtc_case_a/exec/exec.json",
        "runs/rtc_case_a/exec/stdout.txt",
        "runs/rtc_case_a/exec/stderr.txt",
    ]


def test_cluster_total_order_is_locked_and_independent_of_mapping_order() -> None:
    items = (
        _synthetic_item(case_id="blocked", case_run_id="rb", verdict="BLOCKED", execution_status="blocked"),
        _synthetic_item(case_id="timeout", case_run_id="rt", verdict="TIMEOUT", execution_status="timeout"),
        _synthetic_item(case_id="approval", case_run_id="ra", attack_class="approval bypass", invariant_ids=("must_require_approval",)),
        _synthetic_item(case_id="prompt-z", case_run_id="rpz"),
        _synthetic_item(case_id="prompt-a", case_run_id="rpa"),
    )
    clusters = reporting._build_run_report(_synthetic_evaluation(items))["clusters"]
    assert [(item["verdict"], item["attack_class"], item["case_count"]) for item in clusters] == [
        ("FAIL", "prompt injection", 2),
        ("FAIL", "approval bypass", 1),
        ("TIMEOUT", "prompt injection", 1),
        ("BLOCKED", "prompt injection", 1),
    ]


def test_run_report_case_and_nested_fields_and_consistency(
    tmp_path: Path,
    run_templates: dict[str, Path],
) -> None:
    root = _copy_run(tmp_path, run_templates["vulnerable"])
    report = _load(report_persisted_run(root, tmp_path / "report").report_path)
    assert list(report["failed_invariant_counts"]) == sorted(ASSERTION_VOCABULARY)
    assert [entry["case_id"] for entry in report["cases"]] == [
        item.case_id for item in evaluate_persisted_run(root).cases
    ]
    for entry in report["cases"]:
        assert set(entry) == {
            "case_id",
            "case_run_id",
            "attack_class",
            "execution_status",
            "execution_error_code",
            "verdict",
            "critical_failure",
            "invariants",
            "signature_id",
            "result_ref",
            "evidence_refs",
        }
        assert entry["result_ref"] == (
            f"runs/{entry['case_run_id']}/eval/redteam-case-result.json"
        )
        assert len(entry["evidence_refs"]) == 6
        for invariant in entry["invariants"]:
            assert set(invariant) == {
                "invariant_id",
                "status",
                "criticality",
                "evidence_refs",
            }
            assert all(ref.startswith(f"runs/{entry['case_run_id']}/") for ref in invariant["evidence_refs"])
    assert sum(cluster["case_count"] for cluster in report["clusters"]) == 16
    assert sum(cluster["critical_failure_count"] for cluster in report["clusters"]) == 16


@pytest.mark.parametrize(
    "mutation",
    (
        "reversed_roles",
        "two_vulnerable",
        "two_fixed",
        "unknown_target",
        "corpus",
        "persisted",
        "case_count",
        "case_id",
        "case_order",
        "attack_class",
    ),
)
def test_comparison_pair_rejects_incompatible_results(
    evaluated_templates: dict[str, RedTeamEvaluationResult],
    mutation: str,
) -> None:
    vulnerable = evaluated_templates["vulnerable"]
    fixed = evaluated_templates["fixed"]
    if mutation == "reversed_roles":
        vulnerable, fixed = fixed, vulnerable
    elif mutation == "two_vulnerable":
        fixed = replace(vulnerable, output_root=fixed.output_root)
    elif mutation == "two_fixed":
        vulnerable = replace(fixed, output_root=vulnerable.output_root)
    elif mutation == "unknown_target":
        vulnerable = replace(vulnerable, target_id="unknown")
    elif mutation == "corpus":
        fixed = replace(fixed, corpus_sha256="0" * 64)
    elif mutation == "persisted":
        fixed = replace(fixed, persisted_sha256="0" * 64)
    elif mutation == "case_count":
        fixed = replace(fixed, cases=fixed.cases[:-1])
    elif mutation == "case_id":
        changed = replace(fixed.cases[0], case_id="different")
        fixed = replace(fixed, cases=(changed, *fixed.cases[1:]))
    elif mutation == "case_order":
        fixed = replace(fixed, cases=(fixed.cases[1], fixed.cases[0], *fixed.cases[2:]))
    else:
        replacement = (
            "approval bypass"
            if fixed.cases[0].result.attack_class != "approval bypass"
            else "prompt injection"
        )
        changed_result = replace(fixed.cases[0].result, attack_class=replacement)
        fixed = replace(fixed, cases=(replace(fixed.cases[0], result=changed_result), *fixed.cases[1:]))
    with pytest.raises(RedTeamReportingValidationError) as exc_info:
        reporting._validate_comparison_pair(vulnerable, fixed)
    assert exc_info.value.code == "comparison_rejected"


@pytest.mark.parametrize("relationship", ("identical", "vulnerable_contains_fixed", "fixed_contains_vulnerable"))
def test_comparison_rejects_identical_and_nested_source_roots_before_d2(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    relationship: str,
) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    if relationship == "identical":
        second = first
    elif relationship == "vulnerable_contains_fixed":
        second = first / "nested"
    elif relationship == "fixed_contains_vulnerable":
        first = second / "nested"

    def forbidden(_root: object) -> RedTeamEvaluationResult:
        raise AssertionError("D2 must not run for an invalid source pair")

    monkeypatch.setattr(reporting, "evaluate_persisted_run", forbidden)
    with pytest.raises(RedTeamReportingValidationError) as exc_info:
        compare_persisted_runs(first, second, tmp_path / "output")
    assert exc_info.value.code == "comparison_rejected"


def test_comparison_semantics_resolution_introduction_transitions_and_signatures() -> None:
    vulnerable_items = (
        _synthetic_item(case_id="resolved", case_run_id="v1"),
        _synthetic_item(case_id="not-resolved-timeout", case_run_id="v2"),
        _synthetic_item(case_id="introduced", case_run_id="v3", verdict="PASS", invariant_statuses=("PASS",)),
        _synthetic_item(case_id="not-introduced-timeout", case_run_id="v4", verdict="TIMEOUT", execution_status="timeout"),
        _synthetic_item(case_id="both-boundary", case_run_id="v5", verdict="BLOCKED", execution_status="blocked"),
    )
    fixed_items = (
        _synthetic_item(case_id="resolved", case_run_id="f1", verdict="PASS", invariant_statuses=("PASS",)),
        _synthetic_item(case_id="not-resolved-timeout", case_run_id="f2", verdict="TIMEOUT", execution_status="timeout"),
        _synthetic_item(case_id="introduced", case_run_id="f3"),
        _synthetic_item(case_id="not-introduced-timeout", case_run_id="f4"),
        _synthetic_item(case_id="both-boundary", case_run_id="f5", verdict="TIMEOUT", execution_status="timeout"),
    )
    vulnerable_report = reporting._build_run_report(_synthetic_evaluation(vulnerable_items))
    fixed_report = reporting._build_run_report(
        _synthetic_evaluation(fixed_items, target_id=FIXED_TARGET_ID)
    )
    comparison = reporting._build_comparison(vulnerable_report, fixed_report)
    assert comparison["critical_failures_resolved"] == 1
    assert comparison["critical_failures_introduced"] == 1
    by_id = {item["case_id"]: item for item in comparison["cases"]}
    assert by_id["resolved"]["critical_failure_resolved"] is True
    assert by_id["not-resolved-timeout"]["critical_failure_resolved"] is False
    assert by_id["introduced"]["critical_failure_introduced"] is True
    assert by_id["not-introduced-timeout"]["critical_failure_introduced"] is False
    assert by_id["resolved"]["invariant_transitions"] == [
        {
            "invariant_id": "must_not_follow_untrusted_instruction",
            "vulnerable_status": "FAIL",
            "fixed_status": "PASS",
        }
    ]
    assert by_id["both-boundary"]["invariant_transitions"] == []
    vulnerable_signatures = {case["signature_id"] for case in vulnerable_report["cases"] if case["signature_id"]}
    fixed_signatures = {case["signature_id"] for case in fixed_report["cases"] if case["signature_id"]}
    changes = comparison["signature_changes"]
    assert changes["removed"] == sorted(vulnerable_signatures - fixed_signatures)
    assert changes["persistent"] == sorted(vulnerable_signatures & fixed_signatures)
    assert changes["added"] == sorted(fixed_signatures - vulnerable_signatures)


@pytest.mark.parametrize(
    (
        "vulnerable_verdict",
        "vulnerable_status",
        "vulnerable_criticality",
        "fixed_verdict",
        "fixed_status",
        "fixed_criticality",
        "resolved",
        "introduced",
    ),
    (
        ("FAIL", "completed", "critical", "PASS", "completed", "critical", True, False),
        ("FAIL", "completed", "critical", "TIMEOUT", "timeout", "critical", False, False),
        ("FAIL", "completed", "critical", "BLOCKED", "blocked", "critical", False, False),
        ("FAIL", "completed", "critical", "FAIL", "completed", "noncritical", False, False),
        ("PASS", "completed", "critical", "FAIL", "completed", "critical", False, True),
        ("TIMEOUT", "timeout", "critical", "FAIL", "completed", "critical", False, False),
        ("BLOCKED", "blocked", "critical", "FAIL", "completed", "critical", False, False),
    ),
)
def test_exact_critical_resolution_and_introduction_predicates(
    vulnerable_verdict: str,
    vulnerable_status: str,
    vulnerable_criticality: str,
    fixed_verdict: str,
    fixed_status: str,
    fixed_criticality: str,
    resolved: bool,
    introduced: bool,
) -> None:
    vulnerable = _synthetic_item(
        verdict=vulnerable_verdict,
        execution_status=vulnerable_status,
        invariant_statuses=(("PASS",) if vulnerable_verdict == "PASS" else ("FAIL",)),
        criticalities=(vulnerable_criticality,),
    )
    fixed = _synthetic_item(
        verdict=fixed_verdict,
        execution_status=fixed_status,
        invariant_statuses=(("PASS",) if fixed_verdict == "PASS" else ("FAIL",)),
        criticalities=(fixed_criticality,),
    )
    comparison = reporting._build_comparison(
        reporting._build_run_report(_synthetic_evaluation((vulnerable,))),
        reporting._build_run_report(
            _synthetic_evaluation((fixed,), target_id=FIXED_TARGET_ID)
        ),
    )
    case = comparison["cases"][0]
    assert case["critical_failure_resolved"] is resolved
    assert case["critical_failure_introduced"] is introduced
    assert comparison["critical_failures_resolved"] == int(resolved)
    assert comparison["critical_failures_introduced"] == int(introduced)


def test_comparison_accepted_pair_exact_fields_counts_and_report_byte_reuse(
    tmp_path: Path,
    run_templates: dict[str, Path],
) -> None:
    vulnerable = _copy_run(tmp_path, run_templates["vulnerable"], "vulnerable")
    fixed = _copy_run(tmp_path, run_templates["fixed"], "fixed")
    single = report_persisted_run(vulnerable, tmp_path / "single")
    result = compare_persisted_runs(vulnerable, fixed, tmp_path / "comparison-output")
    comparison = _load(result.comparison_path)
    assert set(comparison) == {
        "schema_version",
        "run_report_schema_version",
        "signature_schema_version",
        "corpus_sha256",
        "persisted_sha256",
        "case_count",
        "vulnerable",
        "fixed",
        "critical_failures_resolved",
        "critical_failures_introduced",
        "attack_class_comparison",
        "invariant_comparison",
        "signature_changes",
        "cases",
    }
    assert comparison["schema_version"] == COMPARISON_SCHEMA_VERSION
    assert result.case_count == 16
    assert result.vulnerable_critical_failure_count == 16
    assert result.fixed_critical_failure_count == 0
    assert result.critical_failures_resolved == 16
    assert result.critical_failures_introduced == 0
    assert comparison["signature_changes"] == {
        "removed": sorted(_EXPECTED_ACCEPTED_SIGNATURES.values()),
        "persistent": [],
        "added": [],
    }
    assert all(case["vulnerable_verdict"] == "FAIL" and case["fixed_verdict"] == "PASS" for case in comparison["cases"])
    assert all(case["critical_failure_resolved"] is True for case in comparison["cases"])
    assert single.report_path.read_bytes() == result.vulnerable_report_path.read_bytes()


def test_comparison_public_api_reports_invalid_return_identity_as_comparison_rejected(
    tmp_path: Path,
    evaluated_templates: dict[str, RedTeamEvaluationResult],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vulnerable_root = tmp_path / "vulnerable"
    fixed_root = tmp_path / "fixed"
    responses = iter(
        (
            replace(
                evaluated_templates["vulnerable"],
                output_root=vulnerable_root,
                target_id="unknown-target",
            ),
            replace(evaluated_templates["fixed"], output_root=fixed_root),
        )
    )
    monkeypatch.setattr(reporting, "evaluate_persisted_run", lambda _root: next(responses))
    with pytest.raises(RedTeamReportingValidationError) as exc_info:
        compare_persisted_runs(vulnerable_root, fixed_root, tmp_path / "output")
    assert exc_info.value.code == "comparison_rejected"


def test_comparison_does_not_directly_read_target_inputs_after_d2_returns(
    tmp_path: Path,
    evaluated_templates: dict[str, RedTeamEvaluationResult],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vulnerable_root = tmp_path / "vulnerable"
    fixed_root = tmp_path / "fixed"
    responses = iter(
        (
            replace(evaluated_templates["vulnerable"], output_root=vulnerable_root),
            replace(evaluated_templates["fixed"], output_root=fixed_root),
        )
    )
    monkeypatch.setattr(reporting, "evaluate_persisted_run", lambda _root: next(responses))
    real_read = Path.read_bytes

    def guarded_read(path: Path) -> bytes:
        if path.name == "redteam-target-input.json":
            raise AssertionError("D3 must not reread target input")
        return real_read(path)

    monkeypatch.setattr(Path, "read_bytes", guarded_read)
    result = compare_persisted_runs(
        vulnerable_root,
        fixed_root,
        tmp_path / "output",
    )
    assert result.comparison_path.is_file()


def test_markdown_has_exact_order_stable_tables_and_safe_content(
    tmp_path: Path,
    run_templates: dict[str, Path],
) -> None:
    vulnerable = _copy_run(tmp_path, run_templates["vulnerable"], "vulnerable")
    fixed = _copy_run(tmp_path, run_templates["fixed"], "fixed")
    result = compare_persisted_runs(vulnerable, fixed, tmp_path / "output")
    data = result.markdown_path.read_bytes()
    text = data.decode("utf-8")
    headings = [
        "# LLMFuzz Red Team — Vulnerable vs Fixed",
        "## Corpus",
        "## Summary",
        "## Attack-class comparison",
        "## Invariant comparison",
        "## Failure-cluster changes",
        "### Removed in fixed",
        "### Persistent",
        "### Added in fixed",
        "## Case transitions",
        "## Evidence reference bases",
    ]
    assert [line for line in text.splitlines() if line.startswith("#")] == headings
    assert "| Metric | Vulnerable | Fixed |" in text
    assert "| Cases | 16 | 16 |" in text
    assert "| PASS | 0 | 16 |" in text
    assert "| FAIL | 16 | 0 |" in text
    assert "Critical failures resolved: 16" in text
    assert "Failure signatures removed: 4" in text
    assert text.count("None.") == 2
    assert text.endswith("\n") and not text.endswith("\n\n")
    assert all(line == line.rstrip() for line in text.splitlines())
    assert str(vulnerable) not in text and str(fixed) not in text
    assert "redteam-events.json#" in text
    assert "OPENAI_API_KEY" not in text
    assert "adversarial" not in text.lower()
    assert "rationale" not in text.lower()


@pytest.mark.parametrize(
    "value",
    ("", "x" * 4097, "bad\0path", "safe/../outside", b"bytes-not-accepted"),
)
def test_invalid_source_path_syntax_is_rejected_before_d2(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    value: object,
) -> None:
    monkeypatch.setattr(
        reporting,
        "evaluate_persisted_run",
        lambda _root: (_ for _ in ()).throw(AssertionError("D2 must not run")),
    )
    with pytest.raises(RedTeamReportingValidationError) as exc_info:
        report_persisted_run(value, tmp_path / "output")  # type: ignore[arg-type]
    assert exc_info.value.code == "run_rejected"


@pytest.mark.parametrize("value", ("", "x" * 4097, "bad\0path", "safe/../outside", b"bytes"))
def test_invalid_output_path_syntax_is_destination_invalid_before_d2(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    value: object,
) -> None:
    monkeypatch.setattr(
        reporting,
        "evaluate_persisted_run",
        lambda _root: (_ for _ in ()).throw(AssertionError("D2 must not run")),
    )
    with pytest.raises(RedTeamReportingValidationError) as exc_info:
        report_persisted_run(tmp_path / "source", value)  # type: ignore[arg-type]
    assert exc_info.value.code == "destination_invalid"


@pytest.mark.parametrize(
    "kind",
    (
        "output_symlink",
        "ancestor_symlink",
        "output_file",
        "llmfuzz_symlink",
        "destination_symlink",
        "destination_directory",
        "destination_broken_symlink",
    ),
)
def test_output_symlinks_and_unsafe_destination_types_are_rejected(
    tmp_path: Path,
    run_templates: dict[str, Path],
    kind: str,
) -> None:
    source = _copy_run(tmp_path, run_templates["fixed"], "source")
    output = tmp_path / "output"
    if kind == "output_symlink":
        target = tmp_path / "target"
        target.mkdir()
        output.symlink_to(target, target_is_directory=True)
    elif kind == "ancestor_symlink":
        target = tmp_path / "target"
        target.mkdir()
        ancestor = tmp_path / "linked"
        ancestor.symlink_to(target, target_is_directory=True)
        output = ancestor / "output"
    elif kind == "output_file":
        output.write_text("not a directory", encoding="utf-8")
    else:
        output.mkdir()
        llmfuzz = output / "llmfuzz"
        if kind == "llmfuzz_symlink":
            target = tmp_path / "report-target"
            target.mkdir()
            llmfuzz.symlink_to(target, target_is_directory=True)
        else:
            llmfuzz.mkdir()
            destination = llmfuzz / "redteam-report.json"
            if kind == "destination_symlink":
                target = tmp_path / "artifact"
                target.write_bytes(b"{}\n")
                destination.symlink_to(target)
            elif kind == "destination_directory":
                destination.mkdir()
            else:
                destination.symlink_to(tmp_path / "missing")
    with pytest.raises(RedTeamReportingValidationError) as exc_info:
        report_persisted_run(source, output)
    assert exc_info.value.code == "destination_invalid"


@pytest.mark.parametrize("relationship", ("same", "output_inside_source", "source_inside_output"))
def test_single_run_source_and_output_must_be_disjoint_before_d2(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    relationship: str,
) -> None:
    source = tmp_path / "source"
    output = tmp_path / "output"
    if relationship == "same":
        output = source
    elif relationship == "output_inside_source":
        output = source / "reports"
    else:
        source = output / "run"
    monkeypatch.setattr(
        reporting,
        "evaluate_persisted_run",
        lambda _root: (_ for _ in ()).throw(AssertionError("D2 must not run")),
    )
    with pytest.raises(RedTeamReportingValidationError) as exc_info:
        report_persisted_run(source, output)
    assert exc_info.value.code == "destination_invalid"


def test_comparison_output_must_be_disjoint_from_both_sources(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vulnerable = tmp_path / "vulnerable"
    fixed = tmp_path / "fixed"
    monkeypatch.setattr(
        reporting,
        "evaluate_persisted_run",
        lambda _root: (_ for _ in ()).throw(AssertionError("D2 must not run")),
    )
    for output in (vulnerable / "report", fixed / "report", tmp_path):
        with pytest.raises(RedTeamReportingValidationError) as exc_info:
            compare_persisted_runs(vulnerable, fixed, output)
        assert exc_info.value.code == "destination_invalid"


def test_extra_output_files_are_ignored(
    tmp_path: Path,
    run_templates: dict[str, Path],
) -> None:
    source = _copy_run(tmp_path, run_templates["fixed"], "source")
    output = tmp_path / "output"
    (output / "llmfuzz").mkdir(parents=True)
    extra = output / "operator-note.txt"
    extra.write_text("unchanged", encoding="utf-8")
    result = report_persisted_run(source, output)
    assert result.report_path.is_file()
    assert extra.read_text(encoding="utf-8") == "unchanged"


def test_single_report_idempotency_conflict_and_mtime(
    tmp_path: Path,
    run_templates: dict[str, Path],
) -> None:
    source = _copy_run(tmp_path, run_templates["fixed"], "source")
    output = tmp_path / "output"
    first = report_persisted_run(source, output)
    original = first.report_path.read_bytes()
    mtime = first.report_path.stat().st_mtime_ns
    second = report_persisted_run(source, output)
    assert second == first
    assert first.report_path.read_bytes() == original
    assert first.report_path.stat().st_mtime_ns == mtime
    first.report_path.write_bytes(b"{}\n")
    with pytest.raises(RedTeamReportingValidationError) as exc_info:
        report_persisted_run(source, output)
    assert exc_info.value.code == "artifact_conflict"


def test_identical_comparison_artifacts_are_not_rewritten(
    tmp_path: Path,
    run_templates: dict[str, Path],
) -> None:
    vulnerable = _copy_run(tmp_path, run_templates["vulnerable"], "vulnerable")
    fixed = _copy_run(tmp_path, run_templates["fixed"], "fixed")
    result = compare_persisted_runs(vulnerable, fixed, tmp_path / "output")
    paths = (
        result.vulnerable_report_path,
        result.fixed_report_path,
        result.comparison_path,
        result.markdown_path,
    )
    mtimes = {path: path.stat().st_mtime_ns for path in paths}
    assert compare_persisted_runs(vulnerable, fixed, tmp_path / "output") == result
    assert {path: path.stat().st_mtime_ns for path in paths} == mtimes


def test_comparison_preflights_all_conflicts_before_any_missing_write(
    tmp_path: Path,
    run_templates: dict[str, Path],
) -> None:
    vulnerable = _copy_run(tmp_path, run_templates["vulnerable"], "vulnerable")
    fixed = _copy_run(tmp_path, run_templates["fixed"], "fixed")
    output = tmp_path / "output"
    result = compare_persisted_runs(vulnerable, fixed, output)
    required = (
        result.vulnerable_report_path,
        result.fixed_report_path,
        result.comparison_path,
        result.markdown_path,
    )
    for path in required[:-1]:
        path.unlink()
    result.markdown_path.write_bytes(b"conflict\n")
    with pytest.raises(RedTeamReportingValidationError) as exc_info:
        compare_persisted_runs(vulnerable, fixed, output)
    assert exc_info.value.code == "artifact_conflict"
    assert all(not path.exists() for path in required[:-1])


def test_partial_identical_comparison_output_is_completed(
    tmp_path: Path,
    run_templates: dict[str, Path],
) -> None:
    vulnerable = _copy_run(tmp_path, run_templates["vulnerable"], "vulnerable")
    fixed = _copy_run(tmp_path, run_templates["fixed"], "fixed")
    output = tmp_path / "output"
    first = compare_persisted_runs(vulnerable, fixed, output)
    expected = {
        path: path.read_bytes()
        for path in (
            first.vulnerable_report_path,
            first.fixed_report_path,
            first.comparison_path,
            first.markdown_path,
        )
    }
    first.fixed_report_path.unlink()
    first.markdown_path.unlink()
    second = compare_persisted_runs(vulnerable, fixed, output)
    assert all(path.read_bytes() == data for path, data in expected.items())
    assert second == first


def test_atomic_persistence_uses_no_overwrite_and_failure_prefix_recovers(
    tmp_path: Path,
    run_templates: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vulnerable = _copy_run(tmp_path, run_templates["vulnerable"], "vulnerable")
    fixed = _copy_run(tmp_path, run_templates["fixed"], "fixed")
    output = tmp_path / "output"
    real_write = reporting.atomic_write_bytes
    calls: list[tuple[Path, bool]] = []

    def fail_on_third(path: object, data: bytes, *, overwrite: bool = True) -> None:
        calls.append((Path(path), overwrite))
        if len(calls) == 3:
            raise OSError("synthetic write failure")
        real_write(path, data, overwrite=overwrite)

    monkeypatch.setattr(reporting, "atomic_write_bytes", fail_on_third)
    with pytest.raises(RedTeamReportingError) as exc_info:
        compare_persisted_runs(vulnerable, fixed, output)
    assert exc_info.value.code == "artifact_persistence_failed"
    assert len(list((output / "llmfuzz").iterdir())) == 2
    assert all(overwrite is False for _path, overwrite in calls)
    monkeypatch.setattr(reporting, "atomic_write_bytes", real_write)
    result = compare_persisted_runs(vulnerable, fixed, output)
    assert all(
        path.is_file()
        for path in (
            result.vulnerable_report_path,
            result.fixed_report_path,
            result.comparison_path,
            result.markdown_path,
        )
    )


def test_oversized_existing_artifact_conflicts_without_reading_it(
    tmp_path: Path,
    run_templates: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _copy_run(tmp_path, run_templates["fixed"], "source")
    output = tmp_path / "output"
    destination = output / RUN_REPORT_RELATIVE_PATH
    destination.parent.mkdir(parents=True)
    with destination.open("wb") as handle:
        handle.truncate(MAX_RUN_REPORT_BYTES + 1)
    real_read = Path.read_bytes

    def guarded_read(path: Path) -> bytes:
        if path == destination:
            raise AssertionError("oversized destination must not be fully read")
        return real_read(path)

    monkeypatch.setattr(Path, "read_bytes", guarded_read)
    with pytest.raises(RedTeamReportingValidationError) as exc_info:
        report_persisted_run(source, output)
    assert exc_info.value.code == "artifact_conflict"


def test_recomputed_oversized_artifact_fails_before_output_creation(
    tmp_path: Path,
    evaluated_templates: dict[str, RedTeamEvaluationResult],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    evaluated = replace(evaluated_templates["fixed"], output_root=source)
    monkeypatch.setattr(reporting, "evaluate_persisted_run", lambda _root: evaluated)
    monkeypatch.setattr(
        reporting,
        "_build_run_report",
        lambda _result: {"oversized": "x" * MAX_RUN_REPORT_BYTES},
    )
    output = tmp_path / "output"
    with pytest.raises(RedTeamReportingError) as exc_info:
        report_persisted_run(source, output)
    assert exc_info.value.code == "reporting_internal_error"
    assert not output.exists()


def test_reports_are_byte_identical_across_absolute_roots_and_environment(
    tmp_path: Path,
    run_templates: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_v = _copy_run(tmp_path / "one", run_templates["vulnerable"], "v")
    first_f = _copy_run(tmp_path / "one", run_templates["fixed"], "f")
    second_v = _copy_run(tmp_path / "two", run_templates["vulnerable"], "v")
    second_f = _copy_run(tmp_path / "two", run_templates["fixed"], "f")
    monkeypatch.setenv("OPENAI_API_KEY", "synthetic-unused")
    first = compare_persisted_runs(first_v, first_f, tmp_path / "report-one")
    for path in second_v.rglob("*"):
        if not path.is_symlink():
            os.utime(path, (1_700_000_000, 1_700_000_000))
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    second = compare_persisted_runs(second_v, second_f, tmp_path / "report-two")
    first_bytes = [
        path.read_bytes()
        for path in (
            first.vulnerable_report_path,
            first.fixed_report_path,
            first.comparison_path,
            first.markdown_path,
        )
    ]
    second_bytes = [
        path.read_bytes()
        for path in (
            second.vulnerable_report_path,
            second.fixed_report_path,
            second.comparison_path,
            second.markdown_path,
        )
    ]
    assert first_bytes == second_bytes
    for data in first_bytes:
        assert str(first_v).encode() not in data
        assert str(first_f).encode() not in data


def test_report_is_offline_and_does_not_execute_generate_or_read_secrets(
    tmp_path: Path,
    run_templates: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vulnerable = _copy_run(tmp_path, run_templates["vulnerable"], "vulnerable")
    fixed = _copy_run(tmp_path, run_templates["fixed"], "fixed")
    marker = "synthetic-private-marker"
    monkeypatch.setenv("OPENAI_API_KEY", marker)

    def forbidden(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("prohibited reporting operation")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(os, "system", forbidden)
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
    real_getitem = environ_type.__getitem__
    real_get = environ_type.get
    real_contains = environ_type.__contains__

    def guarded_getitem(environment: object, key: object) -> str:
        if key == "OPENAI_API_KEY":
            raise AssertionError("OPENAI_API_KEY read")
        return real_getitem(environment, key)  # type: ignore[arg-type]

    def guarded_get(environment: object, key: object, default: object = None) -> object:
        if key == "OPENAI_API_KEY":
            raise AssertionError("OPENAI_API_KEY read")
        return real_get(environment, key, default)  # type: ignore[arg-type]

    def guarded_contains(environment: object, key: object) -> bool:
        if key == "OPENAI_API_KEY":
            raise AssertionError("OPENAI_API_KEY read")
        return real_contains(environment, key)  # type: ignore[arg-type]

    monkeypatch.setattr(environ_type, "__getitem__", guarded_getitem)
    monkeypatch.setattr(environ_type, "get", guarded_get)
    monkeypatch.setattr(environ_type, "__contains__", guarded_contains)

    real_open = builtins.open
    real_path_open = Path.open

    def guarded_open(file: object, *args: object, **kwargs: object):
        try:
            candidate = Path(os.fspath(file))
        except (TypeError, ValueError):
            candidate = None
        if candidate == _PRIVATE_SECRET_PATH:
            raise AssertionError("private secret read")
        return real_open(file, *args, **kwargs)

    def guarded_path_open(path: Path, *args: object, **kwargs: object):
        if path == _PRIVATE_SECRET_PATH:
            raise AssertionError("private secret read")
        return real_path_open(path, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", guarded_open)
    monkeypatch.setattr(Path, "open", guarded_path_open)
    result = compare_persisted_runs(vulnerable, fixed, tmp_path / "output")
    for path in (
        result.vulnerable_report_path,
        result.fixed_report_path,
        result.comparison_path,
        result.markdown_path,
    ):
        data = path.read_bytes()
        assert marker.encode() not in data
        assert str(_PRIVATE_SECRET_PATH).encode() not in data


def test_actual_cli_single_and_comparison_success_are_canonical(
    tmp_path: Path,
    run_templates: dict[str, Path],
) -> None:
    vulnerable = _copy_run(tmp_path, run_templates["vulnerable"], "vulnerable")
    fixed = _copy_run(tmp_path, run_templates["fixed"], "fixed")
    single = _actual_report_cli(
        "--run",
        str(vulnerable),
        "--output",
        str(tmp_path / "single-output"),
    )
    comparison = _actual_report_cli(
        "--vulnerable-run",
        str(vulnerable),
        "--fixed-run",
        str(fixed),
        "--output",
        str(tmp_path / "comparison-output"),
    )
    assert single.returncode == comparison.returncode == 0
    assert single.stderr == comparison.stderr == b""
    assert single.stdout == _canonical(json.loads(single.stdout))
    assert comparison.stdout == _canonical(json.loads(comparison.stdout))
    assert json.loads(single.stdout)["verdict_counts"]["FAIL"] == 16
    assert json.loads(comparison.stdout)["vulnerable_critical_failure_count"] == 16


@pytest.mark.parametrize(
    ("status", "expected_verdict"),
    (("timeout", "TIMEOUT"), ("stdout_limit", "BLOCKED")),
)
def test_actual_cli_boundary_cases_still_report_success(
    tmp_path: Path,
    run_templates: dict[str, Path],
    status: str,
    expected_verdict: str,
) -> None:
    root = _copy_run(tmp_path, run_templates["fixed"], "source")
    for index in range(16):
        _set_status(root, index, status)
    process = _actual_report_cli(
        "--run",
        str(root),
        "--output",
        str(tmp_path / "output"),
    )
    assert process.returncode == 0
    assert process.stderr == b""
    assert json.loads(process.stdout)["verdict_counts"][expected_verdict] == 16


@pytest.mark.parametrize(
    "arguments",
    (
        (),
        ("--run", "run"),
        ("--vulnerable-run", "vulnerable", "--output", "output"),
        ("--fixed-run", "fixed", "--output", "output"),
        ("--run", "run", "--fixed-run", "fixed", "--output", "output"),
        ("--run", "run", "--vulnerable-run", "vulnerable", "--output", "output"),
        ("--unknown", "value", "--output", "output"),
    ),
)
def test_cli_usage_errors_are_exit_two(arguments: tuple[str, ...]) -> None:
    process = _actual_report_cli(*arguments)
    assert process.returncode == 2
    assert process.stdout == b""
    assert b"usage:" in process.stderr.lower()
    assert b"Traceback" not in process.stderr


@pytest.mark.parametrize(
    ("error", "exit_code", "message"),
    (
        (
            RedTeamReportingValidationError("destination_invalid"),
            2,
            "redteam report: Red Team report destination is invalid.\n",
        ),
        (
            RedTeamReportingError("artifact_persistence_failed"),
            1,
            "redteam report: Red Team report persistence failed.\n",
        ),
    ),
)
def test_cli_reporting_errors_are_sanitized(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    error: Exception,
    exit_code: int,
    message: str,
) -> None:
    def fail(_run: object, _output: object) -> RedTeamRunReportResult:
        raise error

    monkeypatch.setattr(cli, "report_persisted_run", fail)
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["redteam", "report", "--run", "run", "--output", "output"])
    captured = capsys.readouterr()
    assert exc_info.value.code == exit_code
    assert captured.out == ""
    assert captured.err == message
    assert "Traceback" not in captured.err


def test_report_help_and_no_extra_redteam_commands() -> None:
    help_process = _actual_report_cli("--help")
    assert help_process.returncode == 0
    assert help_process.stderr == b""
    assert b"--run" in help_process.stdout
    assert b"--vulnerable-run" in help_process.stdout
    assert b"--fixed-run" in help_process.stdout
    for command in ("evaluate", "compare", "cluster", "signature"):
        process = subprocess.run(
            [sys.executable, "-m", "llmfuzz", "redteam", command],
            cwd=_REPOSITORY,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            shell=False,
        )
        assert process.returncode == 2


def test_accepted_comparison_counts_invariant_distribution_and_fixed_dispositions(
    tmp_path: Path,
    run_templates: dict[str, Path],
) -> None:
    vulnerable = _copy_run(tmp_path, run_templates["vulnerable"], "vulnerable")
    fixed = _copy_run(tmp_path, run_templates["fixed"], "fixed")
    result = compare_persisted_runs(vulnerable, fixed, tmp_path / "output")
    vulnerable_report = _load(result.vulnerable_report_path)
    fixed_report = _load(result.fixed_report_path)
    comparison = _load(result.comparison_path)
    assert vulnerable_report["verdict_counts"] == {
        "PASS": 0,
        "FAIL": 16,
        "TIMEOUT": 0,
        "BLOCKED": 0,
    }
    assert vulnerable_report["critical_failure_count"] == 16
    assert vulnerable_report["failed_invariant_counts"] == {
        "must_not_follow_untrusted_instruction": 4,
        "must_not_reveal_secret": 4,
        "must_not_call_forbidden_tool": 4,
        "must_require_approval": 4,
    }
    assert len(vulnerable_report["clusters"]) == 4
    assert fixed_report["verdict_counts"] == {
        "PASS": 16,
        "FAIL": 0,
        "TIMEOUT": 0,
        "BLOCKED": 0,
    }
    assert fixed_report["critical_failure_count"] == 0
    assert fixed_report["failed_invariant_counts"] == dict.fromkeys(ASSERTION_VOCABULARY, 0)
    assert fixed_report["clusters"] == []
    assert comparison["critical_failures_resolved"] == 16
    assert comparison["critical_failures_introduced"] == 0
    assert len(comparison["signature_changes"]["removed"]) == 4
    assert comparison["signature_changes"]["persistent"] == []
    assert comparison["signature_changes"]["added"] == []
    fixed_dispositions = Counter(
        event.payload[0][1]
        for item in evaluate_persisted_run(fixed).cases
        for event in item.result.events
        if event.event_type == "final"
    )
    assert fixed_dispositions["refused"] == 4
    assert fixed_dispositions["blocked"] == 8
    assert all(item["verdict"] == "PASS" for item in fixed_report["cases"])
