from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping, Sequence

from .command_allowlist import CONTROLLED_PATH as _CONTROLLED_PATH

def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _decode_text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _resolve_placeholders(s: str, mapping: Mapping[str, str]) -> str:
    out = str(s)
    for token, value in mapping.items():
        out = out.replace(token, value)
    return out


def _temp_path_for(target_path: Path) -> Path:
    directory = target_path.parent
    token = f"{os.getpid()}.{int(time.time() * 1000)}"
    return directory / f".tmp.{token}.{target_path.name}"


def _fsync_dir(path: Path) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY  # type: ignore[attr-defined]
    try:
        fd = os.open(str(path), flags)
    except Exception:
        return
    try:
        os.fsync(fd)
    except Exception:
        pass
    finally:
        try:
            os.close(fd)
        except Exception:
            pass


def _atomic_write_json(path: Path, obj: dict) -> None:
    os.makedirs(path.parent, exist_ok=True)
    text = json.dumps(obj, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
    tmp_path = _temp_path_for(path)
    with open(tmp_path, "w", encoding="utf-8") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp_path, path)
    _fsync_dir(path.parent)


@dataclass(frozen=True)
class ExecEngineResultV01:
    argv: list[str]
    cwd: str
    injected_env: dict[str, str]
    timeout_s: float
    timed_out: bool
    exit_code: int | None
    stdout_text: str
    stderr_text: str
    started_at: str
    ended_at: str
    duration_ms: int
    error: dict[str, str] | None
    exec_json: dict[str, object]


def run_command_target(
    *,
    run_id: str,
    run_dir: Path,
    input_path: Path,
    out_dir: Path,
    argv_template: Sequence[str],
    timeout_s: float,
    extra_env: dict[str, str] | None,
) -> ExecEngineResultV01:
    run_id = str(run_id)
    run_dir = Path(run_dir)
    input_path = Path(input_path)
    out_dir = Path(out_dir)
    timeout_s = float(timeout_s)

    exec_dir = run_dir / "exec"
    os.makedirs(exec_dir, exist_ok=True)

    stdout_path = exec_dir / "stdout.txt"
    stderr_path = exec_dir / "stderr.txt"
    exec_json_path = exec_dir / "exec.json"

    mapping = {
        "<run_id>": run_id,
        "<run_dir>": str(run_dir),
        "<input_path>": str(input_path),
        "<out_dir>": str(out_dir),
    }
    argv: list[str] = []
    for item in argv_template:
        if not isinstance(item, str):
            raise TypeError("argv_template must contain strings")
        argv.append(_resolve_placeholders(item, mapping))

    injected_env = {
        "LLMFUZZ_RUN_ID": run_id,
        "LLMFUZZ_RUN_DIR": str(run_dir),
        "LLMFUZZ_INPUT_PATH": str(input_path),
        "LLMFUZZ_OUT_DIR": str(out_dir),
    }

    env = dict(injected_env)
    if extra_env:
        env.update(extra_env)

    started_at = _utc_now_iso()
    t0 = time.monotonic()
    timed_out = False
    exit_code: int | None = None
    stdout_text = ""
    stderr_text = ""
    error: dict[str, str] | None = None

    try:
        argv0 = str(argv[0])
        if "/" in argv0 or "\\" in argv0:
            argv0_path = Path(argv0)
            if argv0_path.is_absolute():
                pass
            else:
                resolved_path = (run_dir / argv0_path).resolve()
                if not resolved_path.exists():
                    raise ValueError(f"argv[0] did not exist relative to run_dir: {argv0}")
                argv[0] = str(resolved_path)

        else:
            resolved = shutil.which(argv0, path=_CONTROLLED_PATH)
            if not resolved:
                raise ValueError(
                    f"argv[0] did not resolve in controlled PATH ({_CONTROLLED_PATH}): {argv0}"
                )
            argv[0] = str(resolved)
        result = subprocess.run(
            argv,
            cwd=str(run_dir),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
            shell=False,
            timeout=timeout_s,
        )
        exit_code = int(result.returncode)
        stdout_text = _decode_text(result.stdout)
        stderr_text = _decode_text(result.stderr)
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        stdout_text = _decode_text(exc.stdout)
        stderr_text = _decode_text(exc.stderr)
    except Exception as exc:
        timed_out = False
        stdout_text = ""
        stderr_text = ""
        error = {"type": exc.__class__.__name__, "message": str(exc)}
    finally:
        ended_at = _utc_now_iso()
        duration_ms = int(round(max(0.0, time.monotonic() - t0) * 1000))

        try:
            stdout_path.write_text(stdout_text or "", encoding="utf-8", errors="replace")
        except Exception:
            pass
        try:
            stderr_path.write_text(stderr_text or "", encoding="utf-8", errors="replace")
        except Exception:
            pass

        exec_obj: dict[str, object] = {
            "version": "exec_v0.1",
            "run_id": run_id,
            "argv": list(argv),
            "cwd": str(run_dir),
            "started_at": started_at,
            "ended_at": ended_at,
            "duration_ms": int(duration_ms),
            "timeout_s": float(timeout_s),
            "timed_out": bool(timed_out),
            "exit_code": (int(exit_code) if exit_code is not None else None),
            "stdout_path": "exec/stdout.txt",
            "stderr_path": "exec/stderr.txt",
            "error": (dict(error) if error is not None else None),
            "env": dict(injected_env),
        }
        _atomic_write_json(exec_json_path, exec_obj)

    exec_json = json.loads(exec_json_path.read_text(encoding="utf-8"))
    if not isinstance(exec_json, dict):
        raise ValueError("exec.json is not a JSON object")
    return ExecEngineResultV01(
        argv=list(argv),
        cwd=str(run_dir),
        injected_env=dict(injected_env),
        timeout_s=float(timeout_s),
        timed_out=bool(timed_out),
        exit_code=exit_code,
        stdout_text=stdout_text,
        stderr_text=stderr_text,
        started_at=started_at,
        ended_at=ended_at,
        duration_ms=int(duration_ms),
        error=dict(error) if error is not None else None,
        exec_json=exec_json,
    )

