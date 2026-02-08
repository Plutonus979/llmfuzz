"""
Local run:
  cd /tmp/llmfuzz_public_repo
  pytest -q -k quickstart_smoke
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path


_HEX64_LOWER_RE = re.compile(r"^[0-9a-f]{64}$")


def _run_cmd(*, cwd: Path, args: list[str], env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        args,
        cwd=str(cwd),
        env=env,
        capture_output=True,
        text=True,
    )
    return proc


def _assert_ok(proc: subprocess.CompletedProcess[str], *, what: str) -> None:
    if proc.returncode != 0:
        raise AssertionError(
            f"{what} failed (exit={proc.returncode})\n"
            f"cmd: {' '.join(proc.args)}\n"
            f"--- stdout ---\n{proc.stdout}\n"
            f"--- stderr ---\n{proc.stderr}\n"
        )


def test_quickstart_smoke_hello_validate_runone_evalrun(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    hello_spec_path = repo_root / "docs" / "phase3" / "examples" / "fuzzspec_quickstart_hello_command.json"
    assert hello_spec_path.exists()

    work_root_base = tmp_path / "work_root_base"
    seed_path = tmp_path / "seed.pdf"
    seed_path.write_bytes(b"%PDF-1.4\n%seed\n")

    raw_spec = json.loads(hello_spec_path.read_text(encoding="utf-8"))
    raw_spec["target"]["work_root_base"] = str(work_root_base)
    raw_spec["seed"]["path"] = str(seed_path)
    patched_spec_path = tmp_path / "fuzzspec_quickstart_hello_command.patched.json"
    patched_spec_path.write_text(
        json.dumps(raw_spec, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"

    validate = _run_cmd(
        cwd=repo_root,
        env=env,
        args=["python3", "-m", "llmfuzz", "validate", "--spec", str(patched_spec_path)],
    )
    _assert_ok(validate, what="validate")

    run_one = _run_cmd(
        cwd=repo_root,
        env=env,
        args=["python3", "-m", "llmfuzz", "run-one", "--spec", str(patched_spec_path)],
    )
    _assert_ok(run_one, what="run-one")

    runs_dir = (work_root_base / "runs").resolve()
    run_dir: Path | None = None
    for line in run_one.stdout.splitlines():
        candidate = line.strip()
        if not candidate:
            continue
        p = Path(candidate)
        if not p.is_absolute():
            continue
        if not p.exists():
            continue
        if p.parent.resolve() != runs_dir:
            continue
        run_dir = p
        break

    assert run_dir is not None, f"could not find run_dir in stdout:\n{run_one.stdout}"
    assert run_dir.is_dir()

    run_id = run_dir.name

    eval_run = _run_cmd(
        cwd=repo_root,
        env=env,
        args=[
            "python3",
            "-m",
            "llmfuzz",
            "eval-run",
            "--work-root-base",
            str(work_root_base),
            "--run-id",
            run_id,
        ],
    )
    _assert_ok(eval_run, what="eval-run")

    eval_json_path = work_root_base / "runs" / run_id / "llmfuzz" / "eval.json"
    assert eval_json_path.exists()

    hello_result_path = work_root_base / "runs" / run_id / "out" / "hello_result.json"
    assert hello_result_path.exists()
    hello_obj = json.loads(hello_result_path.read_text(encoding="utf-8"))

    sha256 = hello_obj.get("sha256")
    assert isinstance(sha256, str)
    assert _HEX64_LOWER_RE.fullmatch(sha256), f"sha256 not 64 lowercase hex: {sha256!r}"

    byte_length = hello_obj.get("byte_length")
    assert isinstance(byte_length, int) and not isinstance(byte_length, bool)
    assert byte_length >= 0

