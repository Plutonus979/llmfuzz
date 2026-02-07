from __future__ import annotations

import json
import os
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from .io import atomic_write_json, sha256_file
from .orchestrator_v1 import run_case
from .evaluator_v1 import eval_run_v1
from .spec import collect_reserved_field_warnings, load_spec, validate_spec


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def compute_spec_sha256(spec_path: Path) -> str:
    return sha256_file(str(spec_path))


def default_campaign_id(spec_sha256: str, start_index: int) -> str:
    return f"cmp_{spec_sha256[:8]}_s{int(start_index)}"


def run_id_for_case(campaign_id: str, case_index: int) -> str:
    return f"{campaign_id}_case_{int(case_index):06d}"


def _parse_stop_on(value: str | None) -> set[str]:
    if not value:
        return {"FAIL", "TIMEOUT"}
    parts = [p.strip().upper() for p in value.split(",")]
    return {p for p in parts if p}


def _case_run_root_rel(run_id: str) -> Path:
    return Path("runs") / run_id


def _failure_record_rel(run_id: str) -> Path:
    return Path("runs") / run_id / "eval" / "failure_record.json"


def _context_path_abs(work_root_base: Path, run_id: str) -> Path:
    return work_root_base / "runs" / run_id / "context.json"


def _failure_record_abs(work_root_base: Path, run_id: str) -> Path:
    return work_root_base / "runs" / run_id / "eval" / "failure_record.json"


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _normalize_verdict_for_campaign(raw_verdict: str | None) -> str:
    if not raw_verdict:
        return "BLOCKED"
    name = str(raw_verdict).upper()
    if name == "PASS":
        return "PASS"
    if name == "TIMEOUT":
        return "TIMEOUT"
    if name.startswith("FAIL"):
        return "FAIL"
    if name.startswith("BLOCKED"):
        return "BLOCKED"
    if name == "NONDETERMINISM":
        return "FAIL"
    return "FAIL"


def read_cases_jsonl_done_set(cases_jsonl_path: Path) -> set[int]:
    done: set[int] = set()
    if not cases_jsonl_path.exists():
        return done
    with open(cases_jsonl_path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            idx = obj.get("case_index")
            if isinstance(idx, int):
                done.add(idx)
    return done


def append_case_record(cases_jsonl_path: Path, record: dict) -> None:
    os.makedirs(cases_jsonl_path.parent, exist_ok=True)
    line = json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
    with open(cases_jsonl_path, "a", encoding="utf-8") as handle:
        handle.write(line)
        handle.flush()
        os.fsync(handle.fileno())


def compute_summary_from_jsonl(
    cases_jsonl_path: Path,
    *,
    campaign_id: str,
    spec_sha256: str,
    cases_total_requested: int,
) -> dict:
    counts = {"PASS": 0, "FAIL": 0, "TIMEOUT": 0, "DRY_RUN": 0, "BLOCKED": 0}
    started_at = None
    finished_at = None
    cases_completed = 0
    first_failure = None

    if cases_jsonl_path.exists():
        with open(cases_jsonl_path, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                obj = json.loads(line)
                cases_completed += 1
                ts = obj.get("ts_utc")
                if isinstance(ts, str):
                    if started_at is None:
                        started_at = ts
                    finished_at = ts
                verdict = obj.get("verdict")
                if isinstance(verdict, str) and verdict in counts:
                    counts[verdict] += 1
                if first_failure is None and verdict in ("FAIL", "TIMEOUT"):
                    ci = obj.get("case_index")
                    rid = obj.get("run_id")
                    if isinstance(ci, int) and isinstance(rid, str):
                        first_failure = {"case_index": ci, "run_id": rid}

    if started_at is None:
        started_at = _utc_now_iso()
    if finished_at is None:
        finished_at = _utc_now_iso()

    return {
        "campaign_id": campaign_id,
        "spec_sha256": spec_sha256,
        "started_at_utc": started_at,
        "finished_at_utc": finished_at,
        "cases_total_requested": int(cases_total_requested),
        "cases_completed": int(cases_completed),
        "counts": counts,
        "first_failure": first_failure,
    }


@dataclass(frozen=True)
class CampaignPaths:
    campaign_root: Path
    campaign_json: Path
    cases_jsonl: Path
    summary_json: Path
    lock_path: Path


def _campaign_paths(work_root_base: Path, campaign_id: str) -> CampaignPaths:
    root = work_root_base / "llmfuzz" / "campaigns" / campaign_id
    return CampaignPaths(
        campaign_root=root,
        campaign_json=root / "campaign.json",
        cases_jsonl=root / "cases.jsonl",
        summary_json=root / "summary.json",
        lock_path=root / "locks" / "campaign.lock",
    )


class CampaignLock:
    def __init__(self, lock_path: Path):
        self._lock_path = lock_path
        self._fd: int | None = None

    def __enter__(self):
        os.makedirs(self._lock_path.parent, exist_ok=True)
        try:
            fd = os.open(
                str(self._lock_path),
                os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                0o644,
            )
        except FileExistsError as exc:
            raise RuntimeError(f"campaign already locked: {self._lock_path}") from exc
        self._fd = fd
        payload = f"pid={os.getpid()}\nts_utc={_utc_now_iso()}\n"
        os.write(fd, payload.encode("utf-8"))
        os.fsync(fd)
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            if self._fd is not None:
                os.close(self._fd)
        finally:
            self._fd = None
            try:
                os.unlink(self._lock_path)
            except FileNotFoundError:
                pass
        return False


def _ensure_campaign_json(
    paths: CampaignPaths,
    *,
    campaign_id: str,
    spec_path: Path,
    spec_sha256: str,
    start_index: int,
    resume: bool,
) -> None:
    existed_before = paths.campaign_root.exists()
    os.makedirs(paths.campaign_root, exist_ok=True)
    if paths.campaign_json.exists():
        existing = _read_json(paths.campaign_json)
        existing_sha = existing.get("spec_sha256")
        if existing_sha != spec_sha256:
            raise ValueError(
                f"spec_sha256 mismatch for campaign {campaign_id}: {existing_sha} != {spec_sha256}"
            )
        return
    if resume and existed_before:
        raise ValueError(
            f"campaign.json missing for existing campaign {campaign_id} (resume requires campaign.json)"
        )
    payload = {
        "campaign_id": campaign_id,
        "created_at_utc": _utc_now_iso(),
        "spec_path": str(spec_path),
        "spec_sha256": spec_sha256,
        "start_index": int(start_index),
    }
    atomic_write_json(str(paths.campaign_json), payload)


def _build_blocked_record(
    *,
    campaign_id: str,
    case_index: int,
    run_id: str,
    run_root_rel: Path,
    mode: str,
    reason: str,
) -> dict:
    return {
        "ts_utc": _utc_now_iso(),
        "campaign_id": campaign_id,
        "case_index": int(case_index),
        "run_id": run_id,
        "run_root": run_root_rel.as_posix(),
        "artifact_id": None,
        "input_sha256": None,
        "mode": mode,
        "verdict": "BLOCKED",
        "reason": reason,
        "runner_exit_code": None,
        "timeout": False,
        "elapsed_seconds": 0.0,
        "failure_record": _failure_record_rel(run_id).as_posix(),
    }


def _record_from_run_artifacts(
    *,
    work_root_base: Path,
    campaign_id: str,
    case_index: int,
    run_id: str,
    mode: str,
    plan_only: bool,
) -> dict:
    run_root_rel = _case_run_root_rel(run_id)
    context_path = _context_path_abs(work_root_base, run_id)
    if not context_path.exists():
        raise FileNotFoundError("context.json missing")
    context = _read_json(context_path)
    artifact_id = context.get("artifact_id")
    input_sha256 = context.get("input_sha256")

    fr_path = _failure_record_abs(work_root_base, run_id)
    fr = _read_json(fr_path) if fr_path.exists() else None

    if plan_only:
        verdict = "DRY_RUN"
        reason = "plan_only"
        runner_exit_code = None
        timeout = False
        elapsed_seconds = 0.0
    else:
        raw_verdict = fr.get("verdict") if isinstance(fr, dict) else None
        verdict = _normalize_verdict_for_campaign(raw_verdict)
        reason = fr.get("reason") if isinstance(fr, dict) else "missing_failure_record"
        runner_exit_code = fr.get("runner_exit_code") if isinstance(fr, dict) else None
        timeout = bool(fr.get("timeout")) if isinstance(fr, dict) else False
        elapsed_seconds = (
            float(fr.get("elapsed_seconds")) if isinstance(fr, dict) and fr.get("elapsed_seconds") is not None else 0.0
        )

    return {
        "ts_utc": _utc_now_iso(),
        "campaign_id": campaign_id,
        "case_index": int(case_index),
        "run_id": run_id,
        "run_root": run_root_rel.as_posix(),
        "artifact_id": artifact_id,
        "input_sha256": input_sha256,
        "mode": mode,
        "verdict": verdict,
        "reason": reason,
        "runner_exit_code": runner_exit_code,
        "timeout": timeout,
        "elapsed_seconds": elapsed_seconds,
        "failure_record": _failure_record_rel(run_id).as_posix(),
    }


@dataclass(frozen=True)
class CampaignResult:
    campaign_id: str
    campaign_root: Path


def run_campaign(
    *,
    spec_path: Path,
    cases: int,
    start_index: int = 0,
    exec_cases: bool = False,
    timeout_s: int | None = None,
    campaign_id: str | None = None,
    stop_on: str | None = None,
    resume: bool = False,
) -> CampaignResult:
    spec_path = Path(spec_path)
    raw = load_spec(str(spec_path))
    spec = validate_spec(raw)
    fields = collect_reserved_field_warnings(spec)
    if fields:
        print(
            "warning: reserved fields not implemented: " + ", ".join(fields),
            file=sys.stderr,
        )
    work_root_base = spec.target.work_root_base

    spec_sha256 = compute_spec_sha256(spec_path)
    if campaign_id is None:
        campaign_id = default_campaign_id(spec_sha256, start_index)

    paths = _campaign_paths(work_root_base, campaign_id)
    _ensure_campaign_json(
        paths,
        campaign_id=campaign_id,
        spec_path=spec_path,
        spec_sha256=spec_sha256,
        start_index=start_index,
        resume=resume,
    )

    stop_set = _parse_stop_on(stop_on)
    done = read_cases_jsonl_done_set(paths.cases_jsonl) if resume else set()

    with CampaignLock(paths.lock_path):
        for case_index in range(int(start_index), int(start_index) + int(cases)):
            if case_index in done:
                continue
            run_id = run_id_for_case(campaign_id, case_index)
            run_root_rel = _case_run_root_rel(run_id)

            t0 = time.time()
            try:
                # Resume reconstruction: if there is an exec artifact but no record yet,
                # reconstruct only if context.json exists (required for artifact_id/input_sha256).
                fr_path = _failure_record_abs(work_root_base, run_id)
                ctx_path = _context_path_abs(work_root_base, run_id)
                if resume and fr_path.exists() and ctx_path.exists():
                    fr = _read_json(fr_path)
                    if isinstance(fr, dict) and fr.get("reason") == "dry_run":
                        record = _record_from_run_artifacts(
                            work_root_base=work_root_base,
                            campaign_id=campaign_id,
                            case_index=case_index,
                            run_id=run_id,
                            mode="PLAN",
                            plan_only=True,
                        )
                    else:
                        record = _record_from_run_artifacts(
                            work_root_base=work_root_base,
                            campaign_id=campaign_id,
                            case_index=case_index,
                            run_id=run_id,
                            mode="EXEC",
                            plan_only=False,
                        )
                else:
                    run_case(
                        spec_path,
                        case_index=case_index,
                        run_id=run_id,
                        dry_run=(not exec_cases),
                        timeout_seconds=timeout_s,
                        emit_warnings=False,
                    )
                    record = _record_from_run_artifacts(
                        work_root_base=work_root_base,
                        campaign_id=campaign_id,
                        case_index=case_index,
                        run_id=run_id,
                        mode=("EXEC" if exec_cases else "PLAN"),
                        plan_only=(not exec_cases),
                    )
            except Exception as exc:
                elapsed = max(0.0, time.time() - t0)
                record = _build_blocked_record(
                    campaign_id=campaign_id,
                    case_index=case_index,
                    run_id=run_id,
                    run_root_rel=run_root_rel,
                    mode=("EXEC" if exec_cases else "PLAN"),
                    reason=f"{exc.__class__.__name__}: {exc}",
                )
                record["elapsed_seconds"] = round(elapsed, 3)

            if exec_cases and record.get("mode") == "EXEC":
                try:
                    ev = eval_run_v1(work_root_base, run_id, patch_failure_record=False)
                    record["signature_v1"] = ev.get("signature_v1")
                    record["verdict_eval"] = ev.get("verdict")
                    if record.get("verdict") in (None, "", "UNKNOWN", "DRY_RUN"):
                        if isinstance(ev.get("verdict"), str) and ev.get("verdict"):
                            record["verdict"] = ev.get("verdict")
                except Exception:
                    pass

            append_case_record(paths.cases_jsonl, record)
            done.add(case_index)

            if record.get("verdict") in stop_set:
                break

        summary = compute_summary_from_jsonl(
            paths.cases_jsonl,
            campaign_id=campaign_id,
            spec_sha256=spec_sha256,
            cases_total_requested=int(cases),
        )
        atomic_write_json(str(paths.summary_json), summary)

    return CampaignResult(campaign_id=campaign_id, campaign_root=paths.campaign_root)

