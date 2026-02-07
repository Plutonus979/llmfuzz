from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

from .classify import (
    ExecutionInfo,
    FailureRecord,
    FailureVerdict,
    InputRef,
    MutationRef,
    OutputRef,
    SpecRef,
    Timestamps,
)
from .exec_engine_v1 import run_command_target
from .io import atomic_write_bytes, atomic_write_json, atomic_write_text, sha256_file
from .mutations import apply_mutations, generate_case, mutations_to_jsonl
from .spec import (
    FuzzSpec,
    collect_reserved_field_warnings,
    load_spec,
    validate_spec,
)


@dataclass
class RunLayout:
    work_root: Path
    run_id: str
    run_dir: Path
    exec_dir: Path
    input_dir: Path
    llmfuzz_dir: Path
    out_dir: Path
    eval_dir: Path
    context_path: Path
    input_pdf_path: Path
    seed_pdf_path: Path
    fuzzspec_path: Path
    seed_meta_path: Path
    mutations_path: Path
    runner_stdout_path: Path
    runner_stderr_path: Path
    exec_path: Path
    failure_record_path: Path
    case_index: int | None = None
    rng_seed: int | None = None
    input_sha256: str | None = None
    policy_fingerprint: str | None = None


@dataclass(frozen=True)
class ExecResult:
    cmd: List[str]
    cwd: str
    env_subset: Dict[str, str]
    timeout_seconds: int
    exit_code: int
    timeout: bool
    elapsed_seconds: float
    stdout: str
    stderr: str
    started_utc: str
    finished_utc: str
    skipped: bool


@dataclass(frozen=True)
class ObservedFile:
    relpath: str
    sha256: str
    size_bytes: int | None


@dataclass(frozen=True)
class OrchestratorResult:
    run_id: str
    run_dir: Path
    failure_record_path: Path
    failure_record: dict


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _is_relative_to(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def _fallback_mutations_jsonl(note: str | None = None) -> str:
    obj: dict[str, object] = {"i": 0, "op": "identity"}
    if note:
        obj["note"] = note
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _validate_run_id(run_id: str) -> None:
    if not isinstance(run_id, str) or run_id == "":
        raise ValueError("run_id must not be empty")
    if "/" in run_id or "\\" in run_id or ".." in run_id:
        raise ValueError("run_id contains forbidden path segments")


def _spec_to_canonical_dict(spec: FuzzSpec) -> dict:
    out: dict[str, object] = {
        "schema_version": spec.schema_version,
        "campaign_id": spec.campaign_id,
        "target": {
            "agent_id": spec.target.agent_id,
            "work_root_base": str(spec.target.work_root_base),
        },
        "seed": {
            "path": str(spec.seed.path),
        },
        "mutations": {
            "cases": int(spec.mutations.cases),
        },
        "execution": {
            "work_root_mode": spec.execution.work_root_mode,
        },
        "outputs": {
            "out_dir": spec.outputs.out_dir,
            "eval_dir": spec.outputs.eval_dir,
        },
    }
    if spec.description is not None:
        out["description"] = spec.description
    if spec.target.engine is not None:
        out["target"]["engine"] = spec.target.engine
    if spec.target.runtime_root is not None:
        out["target"]["runtime_root"] = str(spec.target.runtime_root)
    if spec.target.engine_policy is not None:
        out["target"]["engine_policy"] = str(spec.target.engine_policy)
    if spec.target.run_agent_script is not None:
        out["target"]["run_agent_script"] = str(spec.target.run_agent_script)
    if spec.target.command is not None:
        out["target"]["command"] = list(spec.target.command)
        if spec.target.timeout_s is not None:
            out["target"]["timeout_s"] = float(spec.target.timeout_s)
    if spec.seed.media_type is not None:
        out["seed"]["media_type"] = spec.seed.media_type
    if spec.seed.sha256 is not None:
        out["seed"]["sha256"] = spec.seed.sha256
    if spec.mutations.rng_seed is not None:
        out["mutations"]["rng_seed"] = int(spec.mutations.rng_seed)
    if spec.mutations.max_bytes is not None:
        out["mutations"]["max_bytes"] = int(spec.mutations.max_bytes)
    if spec.mutations.max_ops_per_case is not None:
        out["mutations"]["max_ops_per_case"] = int(spec.mutations.max_ops_per_case)
    if spec.mutations.strategies is not None:
        out["mutations"]["strategies"] = list(spec.mutations.strategies)
    if spec.execution.env_overrides is not None:
        out["execution"]["env_overrides"] = dict(spec.execution.env_overrides)
    if spec.outputs.input_dir is not None:
        out["outputs"]["input_dir"] = spec.outputs.input_dir
    if spec.outputs.llmfuzz_dir is not None:
        out["outputs"]["llmfuzz_dir"] = spec.outputs.llmfuzz_dir
    return out


def resolve_adapter(spec: FuzzSpec):
    raise ValueError("Adapters are not shipped in OSS. Use target.command.")


def _policy_fingerprint(path: Path) -> str | None:
    if not path.exists():
        return None
    try:
        return sha256_file(str(path))
    except OSError:
        return None


def prepare_run_layout(work_root: Path, run_id: str) -> RunLayout:
    run_dir = work_root / "runs" / run_id
    exec_dir = run_dir / "exec"
    input_dir = run_dir / "input"
    llmfuzz_dir = run_dir / "llmfuzz"
    out_dir = run_dir / "out"
    eval_dir = run_dir / "eval"
    for path in (run_dir, exec_dir, input_dir, llmfuzz_dir, out_dir, eval_dir):
        os.makedirs(path, exist_ok=True)
    return RunLayout(
        work_root=work_root,
        run_id=run_id,
        run_dir=run_dir,
        exec_dir=exec_dir,
        input_dir=input_dir,
        llmfuzz_dir=llmfuzz_dir,
        out_dir=out_dir,
        eval_dir=eval_dir,
        context_path=run_dir / "context.json",
        input_pdf_path=input_dir / "original.pdf",
        seed_pdf_path=input_dir / "original.seed.pdf",
        fuzzspec_path=llmfuzz_dir / "fuzzspec.json",
        seed_meta_path=llmfuzz_dir / "seed.json",
        mutations_path=llmfuzz_dir / "mutations.jsonl",
        runner_stdout_path=llmfuzz_dir / "runner.stdout.txt",
        runner_stderr_path=llmfuzz_dir / "runner.stderr.txt",
        exec_path=llmfuzz_dir / "exec.json",
        failure_record_path=eval_dir / "failure_record.json",
    )


def _generate_mutations(
    seed_bytes: bytes,
    rng_seed: int,
    *,
    max_bytes: int | None,
    max_ops_per_case: int | None,
    allowed_ops: list[str] | None,
) -> tuple[list, bytes, str]:
    try:
        muts = generate_case(
            seed_bytes,
            rng_seed=rng_seed,
            max_bytes=max_bytes,
            max_ops_per_case=max_ops_per_case,
            allowed_ops=allowed_ops,
        )
        mutated_bytes = apply_mutations(seed_bytes, muts, max_bytes=max_bytes)
        mutations_jsonl = mutations_to_jsonl(muts)
        if not mutations_jsonl:
            mutations_jsonl = _fallback_mutations_jsonl(note="fallback:empty_mutations")
        return muts, mutated_bytes, mutations_jsonl
    except Exception as exc:
        note = f"fallback:{exc.__class__.__name__}"
        return [], seed_bytes, _fallback_mutations_jsonl(note=note)


def write_llmfuzz_artifacts(
    layout: RunLayout,
    spec_snapshot: dict,
    spec: FuzzSpec,
    *,
    seed_bytes: bytes,
    seed_meta: dict,
    muts: list,
    mutations_jsonl: str,
    mutated_bytes: bytes,
    exec_meta: dict | None,
) -> None:
    del exec_meta

    atomic_write_bytes(str(layout.input_pdf_path), mutated_bytes)
    atomic_write_bytes(str(layout.seed_pdf_path), seed_bytes)
    atomic_write_json(str(layout.fuzzspec_path), spec_snapshot)
    atomic_write_json(str(layout.seed_meta_path), seed_meta)

    atomic_write_text(str(layout.mutations_path), mutations_jsonl + "\n")

    if not layout.input_sha256:
        layout.input_sha256 = _sha256_bytes(mutated_bytes)
    context = {
        "run_id": layout.run_id,
        "input_file": str(layout.input_pdf_path.resolve()),
        "input_sha256": layout.input_sha256,
        "artifact_id": layout.input_sha256[:12],
        "case_index": layout.case_index,
        "rng_seed": layout.rng_seed,
    }
    if spec.target.engine is not None:
        context["engine"] = spec.target.engine
    context["agent_id"] = spec.target.agent_id
    atomic_write_json(str(layout.context_path), context)


def _write_exec_artifacts(layout: RunLayout, exec_result: ExecResult) -> None:
    atomic_write_text(str(layout.runner_stdout_path), exec_result.stdout or "")
    atomic_write_text(str(layout.runner_stderr_path), exec_result.stderr or "")
    exec_meta = {
        "elapsed_seconds": round(exec_result.elapsed_seconds, 3),
        "exit_code": exec_result.exit_code,
        "timeout": exec_result.timeout,
        "timeout_seconds": exec_result.timeout_seconds,
        "cmd": exec_result.cmd,
        "cwd": exec_result.cwd,
        "env_subset": exec_result.env_subset,
        "started_utc": exec_result.started_utc,
        "finished_utc": exec_result.finished_utc,
    }
    atomic_write_json(str(layout.exec_path), exec_meta)


def _write_exec_v01_artifacts(
    layout: RunLayout,
    exec_result: ExecResult,
    *,
    error: dict[str, str] | None,
) -> None:
    exec_dir = layout.exec_dir
    exec_json_path = exec_dir / "exec.json"
    stdout_path = exec_dir / "stdout.txt"
    stderr_path = exec_dir / "stderr.txt"

    atomic_write_text(str(stdout_path), exec_result.stdout or "")
    atomic_write_text(str(stderr_path), exec_result.stderr or "")

    injected_env = {
        "LLMFUZZ_RUN_ID": layout.run_id,
        "LLMFUZZ_RUN_DIR": str(layout.run_dir),
        "LLMFUZZ_INPUT_PATH": str(layout.input_pdf_path),
        "LLMFUZZ_OUT_DIR": str(layout.out_dir),
    }

    exec_obj = {
        "version": "exec_v0.1",
        "run_id": layout.run_id,
        "argv": list(exec_result.cmd),
        "cwd": exec_result.cwd,
        "started_at": exec_result.started_utc,
        "ended_at": exec_result.finished_utc,
        "duration_ms": int(round(exec_result.elapsed_seconds * 1000)),
        "timeout_s": float(exec_result.timeout_seconds),
        "timed_out": bool(exec_result.timeout),
        "exit_code": int(exec_result.exit_code),
        "stdout_path": "exec/stdout.txt",
        "stderr_path": "exec/stderr.txt",
        "error": (dict(error) if error is not None else None),
        "env": dict(injected_env),
    }
    atomic_write_json(str(exec_json_path), exec_obj)


def _coerce_text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def execute_target(
    layout: RunLayout,
    spec: FuzzSpec,
    *,
    timeout_seconds_override: int | None = None,
) -> ExecResult:
    adapter = resolve_adapter(spec)
    cmd = adapter.build_cmd(spec)
    env_subset = adapter.build_env(spec, layout.run_id)
    env_subset.update(
        {
            "LLMFUZZ_RUN_ID": layout.run_id,
            "LLMFUZZ_RUN_DIR": str(layout.run_dir),
            "LLMFUZZ_INPUT_PATH": str(layout.input_pdf_path),
            "LLMFUZZ_OUT_DIR": str(layout.out_dir),
        }
    )
    if spec.execution.env_overrides:
        env_subset.update(spec.execution.env_overrides)
    env = os.environ.copy()
    env.update(env_subset)

    started_utc = _utc_now_iso()
    started = time.time()
    timeout_seconds = int(
        timeout_seconds_override
        if timeout_seconds_override is not None
        else adapter.timeout_seconds(spec)
    )
    try:
        result = subprocess.run(
            cmd,
            cwd=str(layout.run_dir),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
            env=env,
        )
        timeout = False
        exit_code = result.returncode
        stdout = result.stdout or ""
        stderr = result.stderr or ""
    except subprocess.TimeoutExpired as exc:
        timeout = True
        exit_code = -1
        stdout = _coerce_text(exc.stdout)
        stderr = _coerce_text(exc.stderr)
    elapsed_seconds = time.time() - started
    finished_utc = _utc_now_iso()

    exec_result = ExecResult(
        cmd=list(cmd),
        cwd=str(layout.run_dir),
        env_subset=dict(env_subset),
        timeout_seconds=timeout_seconds,
        exit_code=exit_code,
        timeout=timeout,
        elapsed_seconds=elapsed_seconds,
        stdout=stdout,
        stderr=stderr,
        started_utc=started_utc,
        finished_utc=finished_utc,
        skipped=False,
    )
    _write_exec_artifacts(layout, exec_result)
    return exec_result


def collect_observed_outputs(layout: RunLayout, *, agent_id: str) -> list[ObservedFile]:
    observed: list[ObservedFile] = []
    run_dir = layout.run_dir

    out_dir = layout.out_dir
    if out_dir.exists() and out_dir.is_dir():
        candidates: list[Path] = []
        for path in out_dir.rglob("*.json"):
            if not path.is_file():
                continue
            candidates.append(path)
        candidates.sort(
            key=lambda p: str(p.relative_to(run_dir)) if _is_relative_to(p, run_dir) else str(p)
        )
        for path in candidates:
            relpath = (
                str(path.relative_to(run_dir)) if _is_relative_to(path, run_dir) else str(path)
            )
            observed.append(
                ObservedFile(
                    relpath=relpath,
                    sha256=sha256_file(str(path)),
                    size_bytes=path.stat().st_size if path.exists() else None,
                )
            )

    report_path = layout.eval_dir / "report.json"
    if report_path.exists() and report_path.is_file():
        relpath = str(report_path.relative_to(run_dir)) if _is_relative_to(report_path, run_dir) else str(report_path)
        observed.append(
            ObservedFile(
                relpath=relpath,
                sha256=sha256_file(str(report_path)),
                size_bytes=report_path.stat().st_size,
            )
        )

    legacy_root = layout.work_root / "out"
    agent_dir = legacy_root / agent_id
    if agent_dir.exists() and agent_dir.is_dir():
        for path in sorted(agent_dir.glob(f"*_{layout.run_id}.json"), key=lambda p: p.name):
            if not path.is_file():
                continue
            try:
                rel = path.relative_to(layout.work_root)
                relpath = f"__legacy__/{rel}"
            except ValueError:
                relpath = f"__legacy__/{path}"
            observed.append(
                ObservedFile(
                    relpath=relpath,
                    sha256=sha256_file(str(path)),
                    size_bytes=path.stat().st_size,
                )
            )

    observed.sort(key=lambda o: o.relpath)
    return observed


def _select_verdict(name_candidates: list[str], *, default: FailureVerdict) -> FailureVerdict:
    for name in name_candidates:
        try:
            return FailureVerdict(name)
        except Exception:
            continue
    return default


def build_failure_record(
    spec: FuzzSpec,
    layout: RunLayout,
    exec_result: ExecResult,
    observed: list[ObservedFile],
) -> dict:
    input_sha256 = layout.input_sha256 or sha256_file(str(layout.input_pdf_path))
    spec_sha256 = sha256_file(str(layout.fuzzspec_path))
    muts_sha256 = sha256_file(str(layout.mutations_path))

    if exec_result.skipped:
        verdict = _select_verdict(
            ["SKIPPED", "BLOCKED_POLICY"],
            default=FailureVerdict.BLOCKED_POLICY,
        )
        reason = "dry_run"
    elif exec_result.timeout:
        verdict = FailureVerdict.TIMEOUT
        reason = "runner_timeout"
    elif exec_result.exit_code != 0:
        verdict = _select_verdict(
            ["FAIL", "FAIL_EXCEPTION"],
            default=FailureVerdict.FAIL_EXCEPTION,
        )
        reason = "runner_nonzero_exit"
    else:
        verdict = FailureVerdict.PASS
        reason = "runner_ok"

    record = FailureRecord(
        schema_version="llmfuzz.failure_record.v1",
        run_id=layout.run_id,
        campaign_id=spec.campaign_id,
        artifact_id=input_sha256[:12],
        input=InputRef(path=str(layout.input_pdf_path), sha256=input_sha256),
        spec_ref=SpecRef(path=str(layout.fuzzspec_path), sha256=spec_sha256),
        mutation_ref=MutationRef(path=str(layout.mutations_path), sha256=muts_sha256),
        execution=ExecutionInfo(
            exit_code=exec_result.exit_code,
            elapsed_ms=int(round(exec_result.elapsed_seconds * 1000)),
            stderr_tail=None,
        ),
        observed_outputs=[
            OutputRef(path=o.relpath, sha256=o.sha256) for o in observed
        ],
        verdict=verdict,
        reason=reason,
        timestamps=Timestamps(
            started_utc=exec_result.started_utc,
            finished_utc=exec_result.finished_utc,
        ),
    )
    payload = record.to_dict()
    payload["input_sha256"] = input_sha256
    payload["case_index"] = layout.case_index
    payload["rng_seed"] = layout.rng_seed
    payload["mutations_path"] = str(layout.mutations_path)
    payload["runner_exit_code"] = exec_result.exit_code
    payload["timeout"] = exec_result.timeout
    payload["elapsed_seconds"] = round(exec_result.elapsed_seconds, 3)
    payload["cmd"] = list(exec_result.cmd)
    payload["cwd"] = exec_result.cwd
    payload["env_subset"] = dict(exec_result.env_subset)
    payload["timeout_seconds"] = exec_result.timeout_seconds
    if layout.policy_fingerprint:
        payload["policy_fingerprint"] = layout.policy_fingerprint
    return payload


def run_case(
    spec_path: Path,
    case_index: int,
    run_id: str | None,
    *,
    dry_run: bool,
    timeout_seconds: int | None = None,
    emit_warnings: bool = True,
) -> OrchestratorResult:
    raw = load_spec(str(spec_path))
    spec = validate_spec(raw)
    if emit_warnings:
        fields = collect_reserved_field_warnings(spec)
        if fields:
            print(
                "warning: reserved fields not implemented: " + ", ".join(fields),
                file=sys.stderr,
            )

    case_count = int(spec.mutations.cases)
    if case_index < 0 or case_index >= case_count:
        raise ValueError("case_index out of range")
    if spec.mutations.rng_seed is not None:
        rng_seed = int(spec.mutations.rng_seed) + int(case_index)
    else:
        rng_seed = case_index

    if run_id is None:
        run_id = uuid.uuid4().hex
    _validate_run_id(run_id)

    work_root = spec.target.work_root_base
    layout = prepare_run_layout(work_root, run_id)
    layout.case_index = case_index
    layout.rng_seed = rng_seed
    layout.policy_fingerprint = (
        _policy_fingerprint(spec.target.engine_policy)
        if spec.target.engine_policy is not None
        else None
    )

    seed_bytes = spec.seed.path.read_bytes()
    seed_meta = {
        "sha256": _sha256_bytes(seed_bytes),
        "size_bytes": len(seed_bytes),
        "source_path": str(spec.seed.path),
    }
    muts, mutated_bytes, mutations_jsonl = _generate_mutations(
        seed_bytes,
        rng_seed,
        max_bytes=spec.mutations.max_bytes,
        max_ops_per_case=spec.mutations.max_ops_per_case,
        allowed_ops=(
            list(spec.mutations.strategies) if spec.mutations.strategies is not None else None
        ),
    )
    layout.input_sha256 = _sha256_bytes(mutated_bytes)

    spec_snapshot = _spec_to_canonical_dict(spec)
    write_llmfuzz_artifacts(
        layout,
        spec_snapshot,
        spec,
        seed_bytes=seed_bytes,
        seed_meta=seed_meta,
        muts=muts,
        mutations_jsonl=mutations_jsonl,
        mutated_bytes=mutated_bytes,
        exec_meta=None,
    )

    if spec.target.command is not None:
        timeout_s_eff = float(spec.target.timeout_s) if spec.target.timeout_s is not None else 30.0
        if dry_run:
            env_subset = {
                "LLMFUZZ_RUN_ID": layout.run_id,
                "LLMFUZZ_RUN_DIR": str(layout.run_dir),
                "LLMFUZZ_INPUT_PATH": str(layout.input_pdf_path),
                "LLMFUZZ_OUT_DIR": str(layout.out_dir),
            }
            if spec.execution.env_overrides:
                env_subset.update(spec.execution.env_overrides)
            mapping = {
                "<run_id>": layout.run_id,
                "<run_dir>": str(layout.run_dir),
                "<input_path>": str(layout.input_pdf_path),
                "<out_dir>": str(layout.out_dir),
            }
            resolved_cmd: list[str] = []
            for item in spec.target.command:
                out = str(item)
                for token, value in mapping.items():
                    out = out.replace(token, value)
                resolved_cmd.append(out)
            exec_result = ExecResult(
                cmd=resolved_cmd,
                cwd=str(layout.run_dir),
                env_subset=env_subset,
                timeout_seconds=int(timeout_s_eff),
                exit_code=0,
                timeout=False,
                elapsed_seconds=0.0,
                stdout="",
                stderr="",
                started_utc=_utc_now_iso(),
                finished_utc=_utc_now_iso(),
                skipped=True,
            )
            _write_exec_artifacts(layout, exec_result)
            _write_exec_v01_artifacts(
                layout,
                exec_result,
                error={"type": "DryRun", "message": "dry_run"},
            )
        else:
            engine_result = run_command_target(
                run_id=layout.run_id,
                run_dir=layout.run_dir,
                input_path=layout.input_pdf_path,
                out_dir=layout.out_dir,
                argv_template=spec.target.command,
                timeout_s=timeout_s_eff,
                extra_env=(spec.execution.env_overrides or None),
            )
            env_subset = dict(engine_result.injected_env)
            if spec.execution.env_overrides:
                env_subset.update(spec.execution.env_overrides)
            exec_result = ExecResult(
                cmd=list(engine_result.argv),
                cwd=str(layout.run_dir),
                env_subset=env_subset,
                timeout_seconds=int(timeout_s_eff),
                exit_code=(
                    int(engine_result.exit_code) if engine_result.exit_code is not None else -1
                ),
                timeout=bool(engine_result.timed_out),
                elapsed_seconds=float(engine_result.duration_ms) / 1000.0,
                stdout=str(engine_result.stdout_text or ""),
                stderr=str(engine_result.stderr_text or ""),
                started_utc=str(engine_result.started_at),
                finished_utc=str(engine_result.ended_at),
                skipped=False,
            )
            _write_exec_artifacts(layout, exec_result)
    else:
        adapter = resolve_adapter(spec)
        if dry_run:
            cmd = adapter.build_cmd(spec)
            env_subset = adapter.build_env(spec, layout.run_id)
            env_subset.update(
                {
                    "LLMFUZZ_RUN_ID": layout.run_id,
                    "LLMFUZZ_RUN_DIR": str(layout.run_dir),
                    "LLMFUZZ_INPUT_PATH": str(layout.input_pdf_path),
                    "LLMFUZZ_OUT_DIR": str(layout.out_dir),
                }
            )
            if spec.execution.env_overrides:
                env_subset.update(spec.execution.env_overrides)
            timeout_seconds_eff = int(
                timeout_seconds
                if timeout_seconds is not None
                else adapter.timeout_seconds(spec)
            )
            exec_result = ExecResult(
                cmd=list(cmd),
                cwd=str(layout.run_dir),
                env_subset=dict(env_subset),
                timeout_seconds=timeout_seconds_eff,
                exit_code=0,
                timeout=False,
                elapsed_seconds=0.0,
                stdout="",
                stderr="",
                started_utc=_utc_now_iso(),
                finished_utc=_utc_now_iso(),
                skipped=True,
            )
            _write_exec_artifacts(layout, exec_result)
            _write_exec_v01_artifacts(
                layout,
                exec_result,
                error={"type": "DryRun", "message": "dry_run"},
            )
        else:
            exec_result = execute_target(
                layout,
                spec,
                timeout_seconds_override=timeout_seconds,
            )
            _write_exec_artifacts(layout, exec_result)
            _write_exec_v01_artifacts(layout, exec_result, error=None)

    observed = collect_observed_outputs(layout, agent_id=spec.target.agent_id)
    record = build_failure_record(spec, layout, exec_result, observed)
    atomic_write_json(str(layout.failure_record_path), record)

    return OrchestratorResult(
        run_id=layout.run_id,
        run_dir=layout.run_dir,
        failure_record_path=layout.failure_record_path,
        failure_record=record,
    )
