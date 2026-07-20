from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path

from .io import atomic_write_bytes
from .redteam_contracts import CASE_RESULT_SCHEMA_VERSION, CASE_VERDICTS
from .redteam_corpus import (
    ACCEPTED_CORPUS_SHA256,
    ASSERTION_VOCABULARY,
    ATTACK_CLASSES,
)
from .redteam_demo_target import FIXED_TARGET_ID, VULNERABLE_TARGET_ID
from .redteam_evaluation import (
    EvaluatedCase,
    RedTeamEvaluationError,
    RedTeamEvaluationResult,
    RedTeamEvaluationValidationError,
    evaluate_persisted_run,
)
from .redteam_run import ACCEPTED_PERSISTED_SHA256, EXECUTION_STATUSES


SIGNATURE_SCHEMA_VERSION = "llmfuzz.redteam.signature.v1"
RUN_REPORT_SCHEMA_VERSION = "llmfuzz.redteam.report.v1"
COMPARISON_SCHEMA_VERSION = "llmfuzz.redteam.comparison.v1"

EXPECTED_REPORT_CASES = 16
MAX_REPORT_CLUSTERS = 16
MAX_REPORT_PATH_CHARS = 4_096
MAX_RUN_REPORT_BYTES = 262_144
MAX_COMPARISON_REPORT_BYTES = 524_288
MAX_MARKDOWN_REPORT_BYTES = 262_144

SIGNATURE_PREFIX = "rtsig_"
SIGNATURE_ID_LENGTH = 70

RUN_REPORT_RELATIVE_PATH = "llmfuzz/redteam-report.json"
VULNERABLE_REPORT_RELATIVE_PATH = "llmfuzz/redteam-vulnerable-report.json"
FIXED_REPORT_RELATIVE_PATH = "llmfuzz/redteam-fixed-report.json"
COMPARISON_RELATIVE_PATH = "llmfuzz/redteam-comparison.json"
COMPARISON_MARKDOWN_RELATIVE_PATH = "llmfuzz/redteam-comparison.md"

_VERDICT_RANK = {value: index for index, value in enumerate(("FAIL", "TIMEOUT", "BLOCKED"))}
_ATTACK_CLASS_RANK = {value: index for index, value in enumerate(ATTACK_CLASSES)}
_ASSERTION_RANK = {value: index for index, value in enumerate(ASSERTION_VOCABULARY)}
_EXECUTION_STATUS_RANK = {
    value: index for index, value in enumerate(EXECUTION_STATUSES)
}
_INDEXED_EVIDENCE_RE = re.compile(r"#[0-9]+$")


class RedTeamReportingValidationError(ValueError):
    _MESSAGES = {
        "run_rejected": "Red Team report input validation failed.",
        "comparison_rejected": "Red Team report comparison inputs do not match.",
        "destination_invalid": "Red Team report destination is invalid.",
        "artifact_conflict": (
            "Existing Red Team report conflicts with deterministic output."
        ),
    }

    def __init__(self, code: str) -> None:
        self.code = code if code in self._MESSAGES else "run_rejected"
        super().__init__(self._MESSAGES[self.code])


class RedTeamReportingError(RuntimeError):
    _MESSAGES = {
        "evaluation_failed": "Red Team report evaluation failed.",
        "artifact_persistence_failed": "Red Team report persistence failed.",
        "reporting_internal_error": "Red Team reporting failed.",
    }

    def __init__(self, code: str) -> None:
        self.code = code if code in self._MESSAGES else "reporting_internal_error"
        super().__init__(self._MESSAGES[self.code])


@dataclass(frozen=True)
class RedTeamRunReportResult:
    output_root: Path
    report_path: Path
    execution_id: str
    target_id: str
    corpus_sha256: str
    persisted_sha256: str
    case_count: int
    verdict_counts: tuple[tuple[str, int], ...]
    critical_failure_count: int
    cluster_count: int


@dataclass(frozen=True)
class RedTeamComparisonResult:
    output_root: Path
    vulnerable_report_path: Path
    fixed_report_path: Path
    comparison_path: Path
    markdown_path: Path
    corpus_sha256: str
    persisted_sha256: str
    case_count: int
    vulnerable_critical_failure_count: int
    fixed_critical_failure_count: int
    critical_failures_resolved: int
    critical_failures_introduced: int


@dataclass(frozen=True)
class _Artifact:
    path: Path
    data: bytes
    maximum: int


def _reject(code: str = "run_rejected") -> None:
    raise RedTeamReportingValidationError(code)


def _canonical_json_bytes(value: object) -> bytes:
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


def _canonical_path(
    value: str | os.PathLike[str],
    *,
    code: str,
) -> Path:
    try:
        raw = os.fspath(value)
    except (TypeError, ValueError, OSError):
        _reject(code)
    if (
        not isinstance(raw, str)
        or not raw
        or len(raw) > MAX_REPORT_PATH_CHARS
        or "\0" in raw
        or ".." in Path(raw).parts
    ):
        _reject(code)
    return Path(os.path.abspath(raw))


def _contains(parent: Path, child: Path) -> bool:
    try:
        child.relative_to(parent)
    except ValueError:
        return False
    return True


def _require_disjoint(source: Path, output: Path) -> None:
    if _contains(source, output) or _contains(output, source):
        _reject("destination_invalid")


def _evaluate(root: Path) -> RedTeamEvaluationResult:
    try:
        return evaluate_persisted_run(root)
    except RedTeamEvaluationValidationError:
        raise RedTeamReportingValidationError("run_rejected") from None
    except RedTeamEvaluationError:
        raise RedTeamReportingError("evaluation_failed") from None
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise RedTeamReportingError("evaluation_failed") from None


def _validate_evaluation(
    result: object,
    root: Path,
    *,
    code: str = "run_rejected",
) -> RedTeamEvaluationResult:
    if not isinstance(result, RedTeamEvaluationResult):
        _reject(code)
    if (
        result.output_root != root
        or not result.output_root.is_absolute()
        or result.corpus_sha256 != ACCEPTED_CORPUS_SHA256
        or result.persisted_sha256 != ACCEPTED_PERSISTED_SHA256
        or result.target_id not in (VULNERABLE_TARGET_ID, FIXED_TARGET_ID)
        or len(result.cases) != EXPECTED_REPORT_CASES
    ):
        _reject(code)
    seen: set[str] = set()
    for item in result.cases:
        if (
            not isinstance(item, EvaluatedCase)
            or item.case_id in seen
            or item.case_id != item.result.case_id
            or item.execution_status not in EXECUTION_STATUSES
            or item.result.attack_class not in ATTACK_CLASSES
            or item.result.verdict not in CASE_VERDICTS
        ):
            _reject(code)
        seen.add(item.case_id)
    return result


def _critical_failure(item: EvaluatedCase) -> bool:
    return item.result.verdict == "FAIL" and any(
        invariant.status == "FAIL" and invariant.criticality == "critical"
        for invariant in item.result.invariant_results
    )


def _root_reference(case_run_id: str, reference: str) -> str:
    return f"runs/{case_run_id}/{reference}"


def _signature_payload(item: EvaluatedCase) -> dict[str, object] | None:
    if item.result.verdict == "PASS":
        return None
    failed: list[dict[str, str]] = []
    if item.result.verdict == "FAIL":
        failed_results = sorted(
            (
                invariant
                for invariant in item.result.invariant_results
                if invariant.status == "FAIL"
            ),
            key=lambda invariant: _ASSERTION_RANK[invariant.invariant_id],
        )
        for invariant in failed_results:
            scope = (
                "indexed"
                if all(_INDEXED_EVIDENCE_RE.search(ref) for ref in invariant.evidence_refs)
                else "stream"
            )
            failed.append(
                {
                    "invariant_id": invariant.invariant_id,
                    "evidence_scope": scope,
                }
            )
    return {
        "schema_version": SIGNATURE_SCHEMA_VERSION,
        "attack_class": item.result.attack_class,
        "verdict": item.result.verdict,
        "execution_status": item.execution_status,
        "failed_invariants": failed,
    }


def _signature_id(payload: dict[str, object]) -> str:
    return SIGNATURE_PREFIX + hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()


def _case_entry(
    item: EvaluatedCase,
) -> tuple[dict[str, object], dict[str, object] | None]:
    payload = _signature_payload(item)
    signature_id = None if payload is None else _signature_id(payload)
    prefix = f"runs/{item.case_run_id}/"
    invariants = [
        {
            "invariant_id": invariant.invariant_id,
            "status": invariant.status,
            "criticality": invariant.criticality,
            "evidence_refs": [prefix + ref for ref in invariant.evidence_refs],
        }
        for invariant in item.result.invariant_results
    ]
    return (
        {
            "case_id": item.case_id,
            "case_run_id": item.case_run_id,
            "attack_class": item.result.attack_class,
            "execution_status": item.execution_status,
            "execution_error_code": item.execution_error_code,
            "verdict": item.result.verdict,
            "critical_failure": _critical_failure(item),
            "invariants": invariants,
            "signature_id": signature_id,
            "result_ref": _root_reference(
                item.case_run_id,
                "eval/redteam-case-result.json",
            ),
            "evidence_refs": [
                prefix + reference for reference in item.result.evidence_refs
            ],
        },
        payload,
    )


def _verdict_counts(cases: list[dict[str, object]]) -> dict[str, int]:
    return {
        verdict: sum(case["verdict"] == verdict for case in cases)
        for verdict in CASE_VERDICTS
    }


def _failed_invariant_counts(cases: list[dict[str, object]]) -> dict[str, int]:
    counts = {invariant_id: 0 for invariant_id in ASSERTION_VOCABULARY}
    for case in cases:
        for invariant in case["invariants"]:  # type: ignore[union-attr]
            if invariant["status"] == "FAIL":
                counts[invariant["invariant_id"]] += 1
    return counts


def _deduplicated(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _clusters(
    cases: list[dict[str, object]],
    payloads: dict[str, dict[str, object]],
) -> list[dict[str, object]]:
    members: dict[str, list[dict[str, object]]] = {}
    for case in cases:
        signature_id = case["signature_id"]
        if isinstance(signature_id, str):
            members.setdefault(signature_id, []).append(case)

    clusters: list[dict[str, object]] = []
    for signature_id, grouped in members.items():
        payload = payloads[signature_id]
        representative = min(grouped, key=lambda case: str(case["case_id"]))
        if payload["verdict"] == "FAIL":
            failed_ids = {
                item["invariant_id"] for item in payload["failed_invariants"]  # type: ignore[union-attr]
            }
            evidence: list[str] = []
            ordered = sorted(
                (
                    invariant
                    for invariant in representative["invariants"]  # type: ignore[union-attr]
                    if invariant["invariant_id"] in failed_ids
                ),
                key=lambda invariant: _ASSERTION_RANK[invariant["invariant_id"]],
            )
            for invariant in ordered:
                evidence.extend(invariant["evidence_refs"])
            representative_evidence = _deduplicated(evidence)
        else:
            prefix = f"runs/{representative['case_run_id']}/exec/"
            representative_evidence = [
                prefix + "exec.json",
                prefix + "stdout.txt",
                prefix + "stderr.txt",
            ]
        clusters.append(
            {
                "signature_id": signature_id,
                "verdict": payload["verdict"],
                "attack_class": payload["attack_class"],
                "execution_status": payload["execution_status"],
                "failed_invariants": payload["failed_invariants"],
                "case_count": len(grouped),
                "critical_failure_count": sum(
                    bool(case["critical_failure"]) for case in grouped
                ),
                "case_ids": [case["case_id"] for case in grouped],
                "representative_case_id": representative["case_id"],
                "representative_result_ref": representative["result_ref"],
                "representative_evidence_refs": representative_evidence,
            }
        )
    clusters.sort(
        key=lambda cluster: (
            _VERDICT_RANK[cluster["verdict"]],
            -cluster["case_count"],
            _ATTACK_CLASS_RANK[cluster["attack_class"]],
            _EXECUTION_STATUS_RANK[cluster["execution_status"]],
            cluster["signature_id"],
        )
    )
    return clusters


def _build_run_report(result: RedTeamEvaluationResult) -> dict[str, object]:
    cases: list[dict[str, object]] = []
    payloads: dict[str, dict[str, object]] = {}
    for item in result.cases:
        case, payload = _case_entry(item)
        cases.append(case)
        if payload is not None:
            payloads[str(case["signature_id"])] = payload

    verdict_counts = _verdict_counts(cases)
    failed_counts = _failed_invariant_counts(cases)
    critical_count = sum(bool(case["critical_failure"]) for case in cases)
    breakdown = []
    for attack_class in ATTACK_CLASSES:
        attack_cases = [case for case in cases if case["attack_class"] == attack_class]
        breakdown.append(
            {
                "attack_class": attack_class,
                "case_count": len(attack_cases),
                "verdict_counts": _verdict_counts(attack_cases),
                "critical_failure_count": sum(
                    bool(case["critical_failure"]) for case in attack_cases
                ),
                "failed_invariant_counts": _failed_invariant_counts(attack_cases),
            }
        )
    clusters = _clusters(cases, payloads)
    if len(clusters) > MAX_REPORT_CLUSTERS:
        raise RedTeamReportingError("reporting_internal_error")
    return {
        "schema_version": RUN_REPORT_SCHEMA_VERSION,
        "signature_schema_version": SIGNATURE_SCHEMA_VERSION,
        "case_result_schema_version": CASE_RESULT_SCHEMA_VERSION,
        "corpus_sha256": result.corpus_sha256,
        "persisted_sha256": result.persisted_sha256,
        "execution_id": result.execution_id,
        "target_id": result.target_id,
        "case_count": len(cases),
        "verdict_counts": verdict_counts,
        "critical_failure_count": critical_count,
        "failed_invariant_counts": failed_counts,
        "attack_class_breakdown": breakdown,
        "cases": cases,
        "clusters": clusters,
    }


def _validate_comparison_pair(
    vulnerable: RedTeamEvaluationResult,
    fixed: RedTeamEvaluationResult,
) -> None:
    if (
        vulnerable.target_id != VULNERABLE_TARGET_ID
        or fixed.target_id != FIXED_TARGET_ID
        or vulnerable.corpus_sha256 != fixed.corpus_sha256
        or vulnerable.persisted_sha256 != fixed.persisted_sha256
        or len(vulnerable.cases) != len(fixed.cases)
        or len(vulnerable.cases) != EXPECTED_REPORT_CASES
    ):
        _reject("comparison_rejected")
    vulnerable_ids = [item.case_id for item in vulnerable.cases]
    fixed_ids = [item.case_id for item in fixed.cases]
    vulnerable_classes = [item.result.attack_class for item in vulnerable.cases]
    fixed_classes = [item.result.attack_class for item in fixed.cases]
    if vulnerable_ids != fixed_ids or vulnerable_classes != fixed_classes:
        _reject("comparison_rejected")


def _invariant_statuses(case: dict[str, object]) -> dict[str, str]:
    return {
        invariant["invariant_id"]: invariant["status"]
        for invariant in case["invariants"]  # type: ignore[union-attr]
    }


def _build_comparison(
    vulnerable: dict[str, object],
    fixed: dict[str, object],
) -> dict[str, object]:
    vulnerable_cases = vulnerable["cases"]
    fixed_cases = fixed["cases"]
    cases: list[dict[str, object]] = []
    for vulnerable_case, fixed_case in zip(
        vulnerable_cases, fixed_cases, strict=True  # type: ignore[arg-type]
    ):
        vulnerable_statuses = _invariant_statuses(vulnerable_case)
        fixed_statuses = _invariant_statuses(fixed_case)
        transitions = []
        for invariant_id in ASSERTION_VOCABULARY:
            if invariant_id in vulnerable_statuses or invariant_id in fixed_statuses:
                transitions.append(
                    {
                        "invariant_id": invariant_id,
                        "vulnerable_status": vulnerable_statuses.get(invariant_id),
                        "fixed_status": fixed_statuses.get(invariant_id),
                    }
                )
        resolved = bool(vulnerable_case["critical_failure"]) and fixed_case["verdict"] == "PASS"
        introduced = vulnerable_case["verdict"] == "PASS" and bool(fixed_case["critical_failure"])
        cases.append(
            {
                "case_id": vulnerable_case["case_id"],
                "attack_class": vulnerable_case["attack_class"],
                "vulnerable_verdict": vulnerable_case["verdict"],
                "fixed_verdict": fixed_case["verdict"],
                "vulnerable_critical_failure": vulnerable_case["critical_failure"],
                "fixed_critical_failure": fixed_case["critical_failure"],
                "critical_failure_resolved": resolved,
                "critical_failure_introduced": introduced,
                "vulnerable_signature_id": vulnerable_case["signature_id"],
                "fixed_signature_id": fixed_case["signature_id"],
                "vulnerable_result_ref": vulnerable_case["result_ref"],
                "fixed_result_ref": fixed_case["result_ref"],
                "invariant_transitions": transitions,
            }
        )

    attack_comparison = []
    for attack_class in ATTACK_CLASSES:
        vulnerable_attack = next(
            item
            for item in vulnerable["attack_class_breakdown"]  # type: ignore[union-attr]
            if item["attack_class"] == attack_class
        )
        fixed_attack = next(
            item
            for item in fixed["attack_class_breakdown"]  # type: ignore[union-attr]
            if item["attack_class"] == attack_class
        )
        attack_cases = [case for case in cases if case["attack_class"] == attack_class]
        attack_comparison.append(
            {
                "attack_class": attack_class,
                "case_count": len(attack_cases),
                "vulnerable": {
                    "verdict_counts": vulnerable_attack["verdict_counts"],
                    "critical_failure_count": vulnerable_attack["critical_failure_count"],
                },
                "fixed": {
                    "verdict_counts": fixed_attack["verdict_counts"],
                    "critical_failure_count": fixed_attack["critical_failure_count"],
                },
                "critical_failures_resolved": sum(
                    bool(case["critical_failure_resolved"]) for case in attack_cases
                ),
                "critical_failures_introduced": sum(
                    bool(case["critical_failure_introduced"]) for case in attack_cases
                ),
            }
        )

    invariant_comparison = []
    for invariant_id in ASSERTION_VOCABULARY:
        vulnerable_statuses = [_invariant_statuses(case).get(invariant_id) for case in vulnerable_cases]
        fixed_statuses = [_invariant_statuses(case).get(invariant_id) for case in fixed_cases]
        invariant_comparison.append(
            {
                "invariant_id": invariant_id,
                "vulnerable_fail_count": vulnerable_statuses.count("FAIL"),
                "fixed_fail_count": fixed_statuses.count("FAIL"),
                "resolved_case_count": sum(
                    left == "FAIL" and right == "PASS"
                    for left, right in zip(vulnerable_statuses, fixed_statuses, strict=True)
                ),
                "introduced_case_count": sum(
                    left == "PASS" and right == "FAIL"
                    for left, right in zip(vulnerable_statuses, fixed_statuses, strict=True)
                ),
            }
        )

    vulnerable_signatures = {
        case["signature_id"] for case in vulnerable_cases if case["signature_id"] is not None
    }
    fixed_signatures = {
        case["signature_id"] for case in fixed_cases if case["signature_id"] is not None
    }
    return {
        "schema_version": COMPARISON_SCHEMA_VERSION,
        "run_report_schema_version": RUN_REPORT_SCHEMA_VERSION,
        "signature_schema_version": SIGNATURE_SCHEMA_VERSION,
        "corpus_sha256": vulnerable["corpus_sha256"],
        "persisted_sha256": vulnerable["persisted_sha256"],
        "case_count": vulnerable["case_count"],
        "vulnerable": {
            "target_id": vulnerable["target_id"],
            "execution_id": vulnerable["execution_id"],
            "report_ref": VULNERABLE_REPORT_RELATIVE_PATH,
            "verdict_counts": vulnerable["verdict_counts"],
            "critical_failure_count": vulnerable["critical_failure_count"],
            "cluster_count": len(vulnerable["clusters"]),  # type: ignore[arg-type]
        },
        "fixed": {
            "target_id": fixed["target_id"],
            "execution_id": fixed["execution_id"],
            "report_ref": FIXED_REPORT_RELATIVE_PATH,
            "verdict_counts": fixed["verdict_counts"],
            "critical_failure_count": fixed["critical_failure_count"],
            "cluster_count": len(fixed["clusters"]),  # type: ignore[arg-type]
        },
        "critical_failures_resolved": sum(
            bool(case["critical_failure_resolved"]) for case in cases
        ),
        "critical_failures_introduced": sum(
            bool(case["critical_failure_introduced"]) for case in cases
        ),
        "attack_class_comparison": attack_comparison,
        "invariant_comparison": invariant_comparison,
        "signature_changes": {
            "removed": sorted(vulnerable_signatures - fixed_signatures),
            "persistent": sorted(vulnerable_signatures & fixed_signatures),
            "added": sorted(fixed_signatures - vulnerable_signatures),
        },
        "cases": cases,
    }


def _format_references(references: list[str]) -> str:
    return ", ".join(f"`{reference}`" for reference in references)


def _cluster_change_lines(
    category: str,
    comparison: dict[str, object],
    vulnerable: dict[str, object],
    fixed: dict[str, object],
) -> list[str]:
    signature_ids = set(comparison["signature_changes"][category])  # type: ignore[index]
    ordered_source = fixed if category == "added" else vulnerable
    ordered = [
        cluster
        for cluster in ordered_source["clusters"]  # type: ignore[union-attr]
        if cluster["signature_id"] in signature_ids
    ]
    if not ordered:
        return ["None."]
    vulnerable_clusters = {
        cluster["signature_id"]: cluster
        for cluster in vulnerable["clusters"]  # type: ignore[union-attr]
    }
    fixed_clusters = {
        cluster["signature_id"]: cluster
        for cluster in fixed["clusters"]  # type: ignore[union-attr]
    }
    lines = []
    for cluster in ordered:
        signature_id = cluster["signature_id"]
        vulnerable_cluster = vulnerable_clusters.get(signature_id)
        fixed_cluster = fixed_clusters.get(signature_id)
        if category == "persistent":
            evidence = (
                "vulnerable: "
                + _format_references(vulnerable_cluster["representative_evidence_refs"])
                + "; fixed: "
                + _format_references(fixed_cluster["representative_evidence_refs"])
            )
        else:
            evidence_cluster = vulnerable_cluster if category == "removed" else fixed_cluster
            evidence = _format_references(evidence_cluster["representative_evidence_refs"])
        lines.append(
            f"- `{signature_id}` | attack=`{cluster['attack_class']}` | "
            f"verdict=`{cluster['verdict']}` | status=`{cluster['execution_status']}` | "
            f"vulnerable_cases={0 if vulnerable_cluster is None else vulnerable_cluster['case_count']} | "
            f"fixed_cases={0 if fixed_cluster is None else fixed_cluster['case_count']} | "
            f"vulnerable_representative=`{('none' if vulnerable_cluster is None else vulnerable_cluster['representative_case_id'])}` | "
            f"fixed_representative=`{('none' if fixed_cluster is None else fixed_cluster['representative_case_id'])}` | "
            f"evidence={evidence}"
        )
    return lines


def _render_markdown(
    vulnerable: dict[str, object],
    fixed: dict[str, object],
    comparison: dict[str, object],
) -> bytes:
    vulnerable_counts = vulnerable["verdict_counts"]
    fixed_counts = fixed["verdict_counts"]
    lines = [
        "# LLMFuzz Red Team — Vulnerable vs Fixed",
        "",
        "## Corpus",
        "",
        f"- Corpus SHA-256: `{comparison['corpus_sha256']}`",
        f"- Persisted SHA-256: `{comparison['persisted_sha256']}`",
        f"- Cases: `{comparison['case_count']}`",
        f"- Vulnerable target: `{vulnerable['target_id']}`",
        f"- Fixed target: `{fixed['target_id']}`",
        f"- Vulnerable execution: `{vulnerable['execution_id']}`",
        f"- Fixed execution: `{fixed['execution_id']}`",
        "",
        "## Summary",
        "",
        "| Metric | Vulnerable | Fixed |",
        "|---|---:|---:|",
        f"| Cases | {vulnerable['case_count']} | {fixed['case_count']} |",
        f"| PASS | {vulnerable_counts['PASS']} | {fixed_counts['PASS']} |",
        f"| FAIL | {vulnerable_counts['FAIL']} | {fixed_counts['FAIL']} |",
        f"| TIMEOUT | {vulnerable_counts['TIMEOUT']} | {fixed_counts['TIMEOUT']} |",
        f"| BLOCKED | {vulnerable_counts['BLOCKED']} | {fixed_counts['BLOCKED']} |",
        f"| Critical failures | {vulnerable['critical_failure_count']} | {fixed['critical_failure_count']} |",
        f"| Failure clusters | {len(vulnerable['clusters'])} | {len(fixed['clusters'])} |",
        "",
        f"Critical failures resolved: {comparison['critical_failures_resolved']}",
        f"Critical failures introduced: {comparison['critical_failures_introduced']}",
        f"Failure signatures removed: {len(comparison['signature_changes']['removed'])}",
        f"Failure signatures persistent: {len(comparison['signature_changes']['persistent'])}",
        f"Failure signatures added: {len(comparison['signature_changes']['added'])}",
        "",
        "## Attack-class comparison",
        "",
        "| Attack class | Vulnerable PASS | Vulnerable FAIL | Vulnerable TIMEOUT | Vulnerable BLOCKED | Fixed PASS | Fixed FAIL | Fixed TIMEOUT | Fixed BLOCKED | Vulnerable critical | Fixed critical | Critical resolved | Critical introduced |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for item in comparison["attack_class_comparison"]:
        vulnerable_side = item["vulnerable"]
        fixed_side = item["fixed"]
        lines.append(
            f"| {item['attack_class']} | {vulnerable_side['verdict_counts']['PASS']} | "
            f"{vulnerable_side['verdict_counts']['FAIL']} | {vulnerable_side['verdict_counts']['TIMEOUT']} | "
            f"{vulnerable_side['verdict_counts']['BLOCKED']} | {fixed_side['verdict_counts']['PASS']} | "
            f"{fixed_side['verdict_counts']['FAIL']} | {fixed_side['verdict_counts']['TIMEOUT']} | "
            f"{fixed_side['verdict_counts']['BLOCKED']} | {vulnerable_side['critical_failure_count']} | "
            f"{fixed_side['critical_failure_count']} | {item['critical_failures_resolved']} | "
            f"{item['critical_failures_introduced']} |"
        )
    lines.extend(
        [
            "",
            "## Invariant comparison",
            "",
            "| Invariant | Vulnerable FAIL | Fixed FAIL | Resolved | Introduced |",
            "|---|---:|---:|---:|---:|",
        ]
    )
    for item in comparison["invariant_comparison"]:
        lines.append(
            f"| {item['invariant_id']} | {item['vulnerable_fail_count']} | "
            f"{item['fixed_fail_count']} | {item['resolved_case_count']} | "
            f"{item['introduced_case_count']} |"
        )
    lines.extend(["", "## Failure-cluster changes", "", "### Removed in fixed", ""])
    lines.extend(_cluster_change_lines("removed", comparison, vulnerable, fixed))
    lines.extend(["", "### Persistent", ""])
    lines.extend(_cluster_change_lines("persistent", comparison, vulnerable, fixed))
    lines.extend(["", "### Added in fixed", ""])
    lines.extend(_cluster_change_lines("added", comparison, vulnerable, fixed))
    lines.extend(
        [
            "",
            "## Case transitions",
            "",
            "| Case | Attack class | Vulnerable verdict | Fixed verdict | Critical resolved | Critical introduced | Invariant transitions |",
            "|---|---|---|---|---|---|---|",
        ]
    )
    for case in comparison["cases"]:
        transitions = "; ".join(
            f"`{item['invariant_id']}`: `{item['vulnerable_status'] or 'N/A'}` -> `{item['fixed_status'] or 'N/A'}`"
            for item in case["invariant_transitions"]
        ) or "none"
        lines.append(
            f"| {case['case_id']} | {case['attack_class']} | {case['vulnerable_verdict']} | "
            f"{case['fixed_verdict']} | {'yes' if case['critical_failure_resolved'] else 'no'} | "
            f"{'yes' if case['critical_failure_introduced'] else 'no'} | {transitions} |"
        )
    lines.extend(
        [
            "",
            "## Evidence reference bases",
            "",
            "Vulnerable result and evidence references are relative to the vulnerable run root.",
            "",
            "Fixed result and evidence references are relative to the fixed run root.",
            "",
            "Report references are relative to the report output root.",
        ]
    )
    return ("\n".join(lines) + "\n").encode("utf-8")


def _has_effective_access(path: Path, mode: int) -> bool:
    try:
        return os.access(path, mode, effective_ids=True)
    except (TypeError, NotImplementedError):
        try:
            return os.access(path, mode)
        except OSError:
            return False
    except OSError:
        return False


def _preflight_output_root(root: Path) -> tuple[bool, bool]:
    existing_ancestor: Path | None = None
    for component in (*reversed(root.parents), root):
        if not os.path.lexists(component):
            break
        try:
            mode = os.lstat(component).st_mode
        except OSError:
            _reject("destination_invalid")
        if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
            _reject("destination_invalid")
        if not _has_effective_access(component, os.X_OK):
            _reject("destination_invalid")
        existing_ancestor = component
    if existing_ancestor is None:
        _reject("destination_invalid")
    root_exists = os.path.lexists(root)
    if not root_exists and not _has_effective_access(
        existing_ancestor, os.W_OK | os.X_OK
    ):
        _reject("destination_invalid")
    llmfuzz_root = root / "llmfuzz"
    llmfuzz_exists = os.path.lexists(llmfuzz_root)
    if llmfuzz_exists:
        try:
            mode = os.lstat(llmfuzz_root).st_mode
        except OSError:
            _reject("destination_invalid")
        if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
            _reject("destination_invalid")
        if not _has_effective_access(llmfuzz_root, os.X_OK):
            _reject("destination_invalid")
    return root_exists, llmfuzz_exists


def _preflight_artifacts(artifacts: tuple[_Artifact, ...]) -> tuple[bool, ...]:
    if not artifacts:
        return ()
    root = artifacts[0].path.parent.parent
    root_exists, llmfuzz_exists = _preflight_output_root(root)
    llmfuzz_root = root / "llmfuzz"
    existing: list[bool] = []
    for artifact in artifacts:
        if not os.path.lexists(artifact.path):
            existing.append(False)
            continue
        try:
            artifact_stat = os.lstat(artifact.path)
        except OSError:
            _reject("destination_invalid")
        if stat.S_ISLNK(artifact_stat.st_mode) or not stat.S_ISREG(
            artifact_stat.st_mode
        ):
            _reject("destination_invalid")
        if artifact_stat.st_size > artifact.maximum:
            _reject("artifact_conflict")
        if not _has_effective_access(artifact.path, os.R_OK):
            _reject("destination_invalid")
        try:
            data = artifact.path.read_bytes()
        except OSError:
            _reject("destination_invalid")
        if data != artifact.data:
            _reject("artifact_conflict")
        existing.append(True)
    if not all(existing):
        writable_parent = llmfuzz_root if llmfuzz_exists else root
        if root_exists and not _has_effective_access(
            writable_parent, os.W_OK | os.X_OK
        ):
            _reject("destination_invalid")
    return tuple(existing)


def _bounded_artifact(path: Path, data: bytes, maximum: int) -> _Artifact:
    if len(data) > maximum:
        raise RedTeamReportingError("reporting_internal_error")
    return _Artifact(path, data, maximum)


def _persist_artifacts(
    output_root: Path,
    artifacts: tuple[_Artifact, ...],
    existing: tuple[bool, ...],
) -> None:
    try:
        if not os.path.lexists(output_root):
            output_root.mkdir(mode=0o755, parents=True)
        llmfuzz_root = output_root / "llmfuzz"
        if not os.path.lexists(llmfuzz_root):
            llmfuzz_root.mkdir(mode=0o755)
        for artifact, already_exists in zip(artifacts, existing, strict=True):
            if not already_exists:
                atomic_write_bytes(artifact.path, artifact.data, overwrite=False)
    except OSError:
        raise RedTeamReportingError("artifact_persistence_failed") from None


def _report_persisted_run(
    run_root: str | os.PathLike[str],
    output_root: str | os.PathLike[str],
) -> RedTeamRunReportResult:
    source = _canonical_path(run_root, code="run_rejected")
    output = _canonical_path(output_root, code="destination_invalid")
    _require_disjoint(source, output)
    evaluated = _validate_evaluation(_evaluate(source), source)
    report = _build_run_report(evaluated)
    report_path = output / RUN_REPORT_RELATIVE_PATH
    artifact = _bounded_artifact(
        report_path,
        _canonical_json_bytes(report),
        MAX_RUN_REPORT_BYTES,
    )
    existing = _preflight_artifacts((artifact,))
    _persist_artifacts(output, (artifact,), existing)
    counts = report["verdict_counts"]
    return RedTeamRunReportResult(
        output,
        report_path,
        evaluated.execution_id,
        evaluated.target_id,
        evaluated.corpus_sha256,
        evaluated.persisted_sha256,
        len(evaluated.cases),
        tuple((verdict, counts[verdict]) for verdict in CASE_VERDICTS),
        report["critical_failure_count"],
        len(report["clusters"]),
    )


def report_persisted_run(
    run_root: str | os.PathLike[str],
    output_root: str | os.PathLike[str],
) -> RedTeamRunReportResult:
    try:
        return _report_persisted_run(run_root, output_root)
    except (RedTeamReportingValidationError, RedTeamReportingError):
        raise
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise RedTeamReportingError("reporting_internal_error") from None


def _compare_persisted_runs(
    vulnerable_run_root: str | os.PathLike[str],
    fixed_run_root: str | os.PathLike[str],
    output_root: str | os.PathLike[str],
) -> RedTeamComparisonResult:
    vulnerable_root = _canonical_path(vulnerable_run_root, code="run_rejected")
    fixed_root = _canonical_path(fixed_run_root, code="run_rejected")
    output = _canonical_path(output_root, code="destination_invalid")
    if _contains(vulnerable_root, fixed_root) or _contains(fixed_root, vulnerable_root):
        _reject("comparison_rejected")
    _require_disjoint(vulnerable_root, output)
    _require_disjoint(fixed_root, output)

    vulnerable = _validate_evaluation(
        _evaluate(vulnerable_root),
        vulnerable_root,
        code="comparison_rejected",
    )
    fixed = _validate_evaluation(
        _evaluate(fixed_root),
        fixed_root,
        code="comparison_rejected",
    )
    _validate_comparison_pair(vulnerable, fixed)
    vulnerable_report = _build_run_report(vulnerable)
    fixed_report = _build_run_report(fixed)
    comparison = _build_comparison(vulnerable_report, fixed_report)
    markdown = _render_markdown(vulnerable_report, fixed_report, comparison)

    vulnerable_report_path = output / VULNERABLE_REPORT_RELATIVE_PATH
    fixed_report_path = output / FIXED_REPORT_RELATIVE_PATH
    comparison_path = output / COMPARISON_RELATIVE_PATH
    markdown_path = output / COMPARISON_MARKDOWN_RELATIVE_PATH
    artifacts = (
        _bounded_artifact(
            vulnerable_report_path,
            _canonical_json_bytes(vulnerable_report),
            MAX_RUN_REPORT_BYTES,
        ),
        _bounded_artifact(
            fixed_report_path,
            _canonical_json_bytes(fixed_report),
            MAX_RUN_REPORT_BYTES,
        ),
        _bounded_artifact(
            comparison_path,
            _canonical_json_bytes(comparison),
            MAX_COMPARISON_REPORT_BYTES,
        ),
        _bounded_artifact(markdown_path, markdown, MAX_MARKDOWN_REPORT_BYTES),
    )
    existing = _preflight_artifacts(artifacts)
    _persist_artifacts(output, artifacts, existing)
    return RedTeamComparisonResult(
        output,
        vulnerable_report_path,
        fixed_report_path,
        comparison_path,
        markdown_path,
        vulnerable.corpus_sha256,
        vulnerable.persisted_sha256,
        len(vulnerable.cases),
        vulnerable_report["critical_failure_count"],
        fixed_report["critical_failure_count"],
        comparison["critical_failures_resolved"],
        comparison["critical_failures_introduced"],
    )


def compare_persisted_runs(
    vulnerable_run_root: str | os.PathLike[str],
    fixed_run_root: str | os.PathLike[str],
    output_root: str | os.PathLike[str],
) -> RedTeamComparisonResult:
    try:
        return _compare_persisted_runs(
            vulnerable_run_root,
            fixed_run_root,
            output_root,
        )
    except (RedTeamReportingValidationError, RedTeamReportingError):
        raise
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise RedTeamReportingError("reporting_internal_error") from None
