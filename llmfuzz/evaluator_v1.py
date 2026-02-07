from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path

from .io import atomic_write_json


_WHITESPACE_RE = re.compile(r"\s+")
_WIN_ABS_PATH_RE = re.compile(r"\b[A-Za-z]:\\[^\s\"']+")
_UNIX_ABS_PATH_RE = re.compile(r"(?<!\w)/(?:[^\s\"']+)")
_STDERR_TAIL_BYTES = 4096
_STDERR_NONEMPTY_SENTINEL = "<stderr-nonempty>"
_STDERR_MISSING_SENTINEL = "<no-stderr>"
_CHECK_ORDER = (
    "CONTEXT_PRESENT",
    "EXEC_PRESENT",
    "RUNNER_EXIT",
    "OUTPUTS_PRESENT",
    "JSON_PARSE",
)


def _safe_run_rel_path(run_id: str, *parts: str) -> str:
    return (Path("runs") / run_id / Path(*parts)).as_posix()


def _safe_join_run_dir(run_dir: Path, relpath: str) -> Path | None:
    try:
        p = Path(relpath)
    except Exception:
        return None
    if p.is_absolute():
        return None
    if ".." in p.parts:
        return None
    # Accept observed_outputs paths like runs/<run_id>/out/foo.json by stripping prefix.
    if len(p.parts) >= 3 and p.parts[0] == "runs" and p.parts[1] == run_dir.name:
        p = Path(*p.parts[2:])
    return run_dir / p


def _normalize_stderr_tail(text: str, run_id: str) -> str:
    if not text:
        return ""
    out = str(text)
    out = _WIN_ABS_PATH_RE.sub("<PATH>", out)
    out = _UNIX_ABS_PATH_RE.sub("<PATH>", out)
    if run_id:
        out = out.replace(run_id, "<RUN_ID>")
    out = _WHITESPACE_RE.sub(" ", out).strip()
    return out


def _sha256_hex16(text: str) -> str:
    digest = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
    return digest[:16]


def _discover_exec_evidence(run_dir: Path) -> dict[str, object]:
    exec_dir = run_dir / "exec"
    llmfuzz_dir = run_dir / "llmfuzz"
    canonical_exec = exec_dir / "exec.json"
    if canonical_exec.exists():
        return {
            "mode": "canonical",
            "exec_json_path": canonical_exec,
            "stdout_path": exec_dir / "stdout.txt",
            "stderr_path": exec_dir / "stderr.txt",
        }
    legacy_exec = llmfuzz_dir / "exec.json"
    if legacy_exec.exists():
        return {
            "mode": "legacy",
            "exec_json_path": legacy_exec,
            "stdout_path": llmfuzz_dir / "runner.stdout.txt",
            "stderr_path": llmfuzz_dir / "runner.stderr.txt",
        }
    return {
        "mode": "missing",
        "exec_json_path": None,
        "stdout_path": None,
        "stderr_path": None,
    }


def _normalize_exec_json(exec_json: dict, mode: str) -> dict:
    if mode != "canonical":
        return exec_json
    out = dict(exec_json)
    if "timeout" not in out:
        timed_out = exec_json.get("timed_out")
        if isinstance(timed_out, bool):
            out["timeout"] = timed_out
    if "timeout_s" not in out and "timeout_seconds" not in out:
        timeout_s = exec_json.get("timeout_s")
        if isinstance(timeout_s, (int, float)):
            out["timeout_s"] = timeout_s
    return out


def _read_stderr_tail(path: Path | None, tail_bytes: int) -> tuple[str, bool]:
    if path is None:
        return "", False
    try:
        size = path.stat().st_size
    except OSError:
        return "", False
    file_nonempty = size > 0
    if not file_nonempty:
        return "", False
    data = b""
    try:
        with open(path, "rb") as handle:
            if size > tail_bytes:
                handle.seek(-tail_bytes, os.SEEK_END)
            data = handle.read()
    except Exception:
        data = b""
    return data.decode("utf-8", errors="replace"), file_nonempty


def eval_run_v1(
    work_root_base: Path,
    run_id: str,
    patch_failure_record: bool = False,
) -> dict:
    """
    Computes verdict + signature_v1 deterministically, writes eval.json, optionally patches failure_record.json.
    Returns the eval dict.
    """
    work_root_base = Path(work_root_base)
    run_id = str(run_id)
    run_dir = work_root_base / "runs" / run_id
    llmfuzz_dir = run_dir / "llmfuzz"
    out_dir = run_dir / "out"

    evidence = _discover_exec_evidence(run_dir)
    context_path = run_dir / "context.json"
    exec_path = evidence.get("exec_json_path")
    if not isinstance(exec_path, Path):
        exec_path = None
    stderr_path = evidence.get("stderr_path")
    if not isinstance(stderr_path, Path):
        stderr_path = None
    failure_record_path = run_dir / "eval" / "failure_record.json"
    eval_path = llmfuzz_dir / "eval.json"

    checks_map: dict[str, dict] = {}

    def _set_check(code: str, status: str, detail: str) -> None:
        checks_map[code] = {"code": code, "status": status, "detail": detail}

    artifact_id = ""
    input_sha256 = ""
    context_ok = False

    # A) Context integrity
    if not context_path.exists():
        _set_check("CONTEXT_PRESENT", "FAIL", "context.json missing")
    else:
        try:
            context = json.loads(context_path.read_text(encoding="utf-8"))
            missing = [k for k in ("run_id", "artifact_id", "input_sha256") if k not in context]
            if missing:
                _set_check("CONTEXT_PRESENT", "FAIL", f"missing fields: {','.join(missing)}")
            else:
                artifact_id = str(context.get("artifact_id") or "")
                input_sha256 = str(context.get("input_sha256") or "")
                context_ok = True
                detail = "ok"
                if (
                    isinstance(input_sha256, str)
                    and len(input_sha256) >= 12
                    and isinstance(artifact_id, str)
                    and artifact_id
                    and artifact_id != input_sha256[:12]
                ):
                    detail = "ok (artifact_id != input_sha256[:12])"
                _set_check("CONTEXT_PRESENT", "PASS", detail)
        except Exception as exc:
            _set_check("CONTEXT_PRESENT", "FAIL", f"json parse error ({exc.__class__.__name__})")

    # Load failure_record (optional)
    failure_record: dict | None = None
    if failure_record_path.exists():
        try:
            failure_record = json.loads(failure_record_path.read_text(encoding="utf-8"))
        except Exception:
            failure_record = None

    # B) Exec integrity
    exec_json: dict | None = None
    if exec_path is None or not exec_path.exists():
        _set_check("EXEC_PRESENT", "FAIL", "exec.json missing")
        verdict = "FAIL"
        signature_v1 = "OUT_MISSING:" + _sha256_hex16("exec.json")
        _set_check("RUNNER_EXIT", "FAIL", "exec_missing")
        _set_check("OUTPUTS_PRESENT", "FAIL", "skipped: verdict=OUT_MISSING")
        _set_check("JSON_PARSE", "FAIL", "skipped: verdict=OUT_MISSING")
    else:
        try:
            exec_json = json.loads(exec_path.read_text(encoding="utf-8"))
        except Exception as exc:
            exec_json = None
            _set_check("EXEC_PRESENT", "FAIL", f"exec.json parse error ({exc.__class__.__name__})")
            verdict = "BLOCKED"
            signature_v1 = "BLOCKED"
            _set_check("RUNNER_EXIT", "FAIL", "blocked")
            _set_check("OUTPUTS_PRESENT", "FAIL", "skipped: verdict=BLOCKED")
            _set_check("JSON_PARSE", "FAIL", "skipped: verdict=BLOCKED")
        else:
            _set_check("EXEC_PRESENT", "PASS", "ok")
            if isinstance(exec_json, dict):
                exec_json = _normalize_exec_json(exec_json, str(evidence.get("mode") or ""))
            fr_reason = str(failure_record.get("reason") or "") if isinstance(failure_record, dict) else ""
            fr_verdict = str(failure_record.get("verdict") or "") if isinstance(failure_record, dict) else ""

            if fr_reason == "dry_run":
                verdict = "DRY_RUN"
                signature_v1 = "DRY_RUN"
                _set_check("RUNNER_EXIT", "FAIL", "dry_run")
                _set_check("OUTPUTS_PRESENT", "FAIL", "skipped: verdict=DRY_RUN")
                _set_check("JSON_PARSE", "FAIL", "skipped: verdict=DRY_RUN")
            elif fr_verdict.startswith("BLOCKED") or fr_verdict == "BLOCKED_POLICY":
                verdict = "BLOCKED"
                signature_v1 = "BLOCKED"
                _set_check("RUNNER_EXIT", "FAIL", "blocked")
                _set_check("OUTPUTS_PRESENT", "FAIL", "skipped: verdict=BLOCKED")
                _set_check("JSON_PARSE", "FAIL", "skipped: verdict=BLOCKED")
            else:
                timeout = bool(exec_json.get("timeout")) if isinstance(exec_json, dict) else False
                exit_code = exec_json.get("exit_code") if isinstance(exec_json, dict) else None
                timeout_s = None
                if isinstance(exec_json, dict):
                    timeout_s = exec_json.get("timeout_s")
                    if timeout_s is None:
                        timeout_s = exec_json.get("timeout_seconds")

                if timeout:
                    verdict = "TIMEOUT"
                    if isinstance(timeout_s, (int, float)) and int(timeout_s) >= 0:
                        signature_v1 = f"TIMEOUT:{int(timeout_s)}"
                    else:
                        signature_v1 = "TIMEOUT"
                elif isinstance(exit_code, int) and exit_code != 0:
                    verdict = "FAIL"
                    stderr_tail = None
                    if isinstance(exec_json, dict):
                        candidate = exec_json.get("stderr_tail")
                        if isinstance(candidate, str) and candidate:
                            stderr_tail = candidate
                        elif candidate not in (None, ""):
                            candidate = str(candidate or "")
                            if candidate:
                                stderr_tail = candidate
                    if stderr_tail is None and isinstance(failure_record, dict):
                        exec_info = failure_record.get("execution")
                        if isinstance(exec_info, dict):
                            candidate = exec_info.get("stderr_tail")
                            if isinstance(candidate, str) and candidate:
                                stderr_tail = candidate
                            elif candidate not in (None, ""):
                                candidate = str(candidate or "")
                                if candidate:
                                    stderr_tail = candidate
                    file_nonempty = False
                    if stderr_tail is None:
                        stderr_tail, file_nonempty = _read_stderr_tail(
                            stderr_path, _STDERR_TAIL_BYTES
                        )
                    else:
                        if stderr_path is not None:
                            try:
                                file_nonempty = stderr_path.stat().st_size > 0
                            except OSError:
                                file_nonempty = False
                    normalized = _normalize_stderr_tail(stderr_tail, run_id)[:_STDERR_TAIL_BYTES]
                    if not normalized:
                        normalized = (
                            _STDERR_NONEMPTY_SENTINEL if file_nonempty else _STDERR_MISSING_SENTINEL
                        )
                    signature_v1 = "CRASH:" + _sha256_hex16(normalized)
                else:
                    verdict = "PASS"
                    signature_v1 = ""

                if timeout:
                    _set_check("RUNNER_EXIT", "FAIL", "timeout=true")
                elif isinstance(exit_code, int) and exit_code == 0:
                    _set_check("RUNNER_EXIT", "PASS", "exit_code=0")
                else:
                    _set_check("RUNNER_EXIT", "FAIL", f"exit_code={exit_code}")

            if verdict in ("TIMEOUT", "FAIL"):
                _set_check("OUTPUTS_PRESENT", "FAIL", f"skipped: verdict={verdict}")
                _set_check("JSON_PARSE", "FAIL", f"skipped: verdict={verdict}")
            elif verdict == "PASS":
                # C) Outputs presence
                observed_paths: list[str] = []
                if isinstance(failure_record, dict):
                    obs = failure_record.get("observed_outputs")
                    if isinstance(obs, list):
                        for item in obs:
                            if isinstance(item, dict) and isinstance(item.get("path"), str):
                                observed_paths.append(item["path"])

                missing_keys: list[str] = []
                existing_candidates: list[tuple[str, Path]] = []
                if observed_paths:
                    for rel in sorted(set(observed_paths)):
                        p = _safe_join_run_dir(run_dir, rel)
                        if p is None or not p.exists():
                            missing_keys.append(Path(rel).name)
                            continue
                        if p.is_file() and p.name.endswith(".json"):
                            existing_candidates.append((Path(rel).as_posix(), p))
                else:
                    for p in sorted(out_dir.glob("*.json"), key=lambda x: x.name):
                        if p.is_file():
                            existing_candidates.append(((Path("out") / p.name).as_posix(), p))

                if not existing_candidates:
                    if not observed_paths:
                        missing_keys = ["NO_OUTPUTS"]
                    sig = "OUT_MISSING:" + _sha256_hex16(",".join(sorted(missing_keys)))
                    verdict = "FAIL"
                    signature_v1 = sig
                    _set_check(
                        "OUTPUTS_PRESENT",
                        "FAIL",
                        f"missing={','.join(sorted(missing_keys))}",
                    )
                    _set_check("JSON_PARSE", "FAIL", "skipped: no outputs")
                else:
                    _set_check("OUTPUTS_PRESENT", "PASS", f"count={len(existing_candidates)}")

                    # D) JSON parse check
                    max_files = 20
                    max_total_bytes = 10 * 1024 * 1024
                    total_bytes = 0
                    parse_ok = True
                    json_bad_detail = None

                    for i, (rel, path) in enumerate(existing_candidates):
                        if i >= max_files:
                            break
                        try:
                            size = path.stat().st_size
                        except OSError:
                            size = 0
                        if total_bytes + size > max_total_bytes:
                            break
                        total_bytes += size
                        try:
                            with open(path, "r", encoding="utf-8") as handle:
                                json.load(handle)
                        except Exception as exc:
                            parse_ok = False
                            base = Path(rel).name
                            err_type = exc.__class__.__name__
                            verdict = "FAIL"
                            signature_v1 = f"JSON_BAD:{base}:{err_type}"
                            json_bad_detail = f"{base} ({err_type})"
                            break

                    if parse_ok:
                        _set_check("JSON_PARSE", "PASS", f"parsed_bytes={total_bytes}")
                        if verdict == "PASS":
                            signature_v1 = "PASS"
                    else:
                        _set_check("JSON_PARSE", "FAIL", f"first_error={json_bad_detail}")

    if verdict == "PASS" and not context_ok:
        verdict = "BLOCKED"
        signature_v1 = "BLOCKED"
        _set_check("RUNNER_EXIT", "FAIL", "blocked")
        _set_check("OUTPUTS_PRESENT", "FAIL", "skipped: verdict=BLOCKED")
        _set_check("JSON_PARSE", "FAIL", "skipped: verdict=BLOCKED")

    if verdict == "PASS" and signature_v1 == "":
        signature_v1 = "PASS"

    checks: list[dict] = []
    for code in _CHECK_ORDER:
        if code not in checks_map:
            checks_map[code] = {"code": code, "status": "FAIL", "detail": "not_evaluated"}
        checks.append(checks_map[code])

    eval_obj = {
        "schema_version": "llmfuzz.eval.v1",
        "run_id": run_id,
        "artifact_id": artifact_id if isinstance(artifact_id, str) else "",
        "input_sha256": input_sha256 if isinstance(input_sha256, str) else "",
        "verdict": verdict,
        "signature_v1": signature_v1,
        "checks": checks,
        "exec_evidence_mode": str(evidence.get("mode") or ""),
        "refs": {
            "context_json": _safe_run_rel_path(run_id, "context.json"),
            "exec_json": (
                _safe_run_rel_path(run_id, "exec", "exec.json")
                if evidence.get("mode") == "canonical"
                else (
                    _safe_run_rel_path(run_id, "llmfuzz", "exec.json")
                    if evidence.get("mode") == "legacy"
                    else ""
                )
            ),
            "failure_record": _safe_run_rel_path(run_id, "eval", "failure_record.json"),
        },
    }

    os.makedirs(llmfuzz_dir, exist_ok=True)
    atomic_write_json(str(eval_path), eval_obj)

    if patch_failure_record:
        if not failure_record_path.exists():
            raise FileNotFoundError(str(failure_record_path))
        if not isinstance(failure_record, dict):
            raise ValueError("failure_record.json is not a JSON object")
        failure_record["signature_v1"] = signature_v1
        failure_record["eval_ref"] = _safe_run_rel_path(run_id, "llmfuzz", "eval.json")
        failure_record["eval_verdict"] = verdict
        atomic_write_json(str(failure_record_path), failure_record)

    return eval_obj

