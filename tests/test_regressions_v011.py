from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]

_SEMVER_RE = re.compile(r"\b\d+\.\d+\.\d+\b")


def _run_llmfuzz(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "llmfuzz", *args],
        cwd=str(_REPO_ROOT),
        capture_output=True,
        text=True,
    )


def test_triage_eval_fallback_reads_work_root_runs(tmp_path: Path) -> None:
    work_root_base = tmp_path / "work_root"
    run_id = "run_001"
    eval_json_path = work_root_base / "runs" / run_id / "llmfuzz" / "eval.json"
    eval_json_path.parent.mkdir(parents=True, exist_ok=True)
    eval_json_path.write_text(
        json.dumps({"verdict": "FAIL", "signature_v1": "SIG1"}, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    campaign_id = "camp_001"
    campaign_root = work_root_base / "llmfuzz" / "campaigns" / campaign_id
    campaign_root.mkdir(parents=True, exist_ok=True)
    (campaign_root / "cases.jsonl").write_text(
        json.dumps({"case_index": 0, "run_id": run_id}, sort_keys=True, separators=(",", ":"))
        + "\n",
        encoding="utf-8",
    )

    proc = _run_llmfuzz(
        "triage-campaign",
        "--work-root-base",
        str(work_root_base),
        "--campaign-id",
        campaign_id,
        "--write-md",
        "false",
        "--patch-summary",
        "false",
    )
    assert proc.returncode == 0, f"triage-campaign failed:\n{proc.stdout}\n{proc.stderr}\n"

    triage_json_path = campaign_root / "triage" / "triage.json"
    triage = json.loads(triage_json_path.read_text(encoding="utf-8"))
    clusters = triage.get("clusters")
    assert isinstance(clusters, list) and clusters
    c0 = clusters[0]
    assert isinstance(c0, dict)
    assert c0.get("verdict_eval") == "FAIL"
    assert c0.get("signature_v1") == "SIG1"


def test_exec_engine_absolute_argv0_is_not_rewritten(tmp_path: Path) -> None:
    work_root_base = tmp_path / "work_root"
    run_id = "run_abs_argv0"
    seed_path = tmp_path / "seed.bin"
    seed_path.write_bytes(b"seed")

    code = (
        "import json,os,pathlib;"
        "p=pathlib.Path(os.environ['LLMFUZZ_OUT_DIR'])/'abs_argv0.json';"
        "p.write_text(json.dumps({'ok':True})+'\\n',encoding='utf-8')"
    )
    spec = {
        "schema_version": "llmfuzz.fuzzspec.v1",
        "campaign_id": "camp_abs_argv0",
        "target": {
            "agent_id": "agent",
            "work_root_base": str(work_root_base),
            "command": [str(Path(sys.executable).resolve()), "-c", code],
        },
        "seed": {"path": str(seed_path)},
        "mutations": {"cases": 1},
        "execution": {},
        "outputs": {"out_dir": "runs/<run_id>/out", "eval_dir": "runs/<run_id>/eval"},
    }
    spec_path = tmp_path / "spec_abs_argv0.json"
    spec_path.write_text(json.dumps(spec, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    proc = _run_llmfuzz("run-one", "--spec", str(spec_path), "--run-id", run_id)
    assert proc.returncode == 0, f"run-one failed:\n{proc.stdout}\n{proc.stderr}\n"
    lines = [ln.strip() for ln in (proc.stdout or "").splitlines() if ln.strip()]
    assert lines, f"run-one stdout empty:\n{proc.stdout}\n{proc.stderr}\n"
    run_dir = Path(lines[0])

    exec_json_path = run_dir / "exec" / "exec.json"
    exec_obj = json.loads(exec_json_path.read_text(encoding="utf-8"))
    argv0 = (exec_obj.get("argv") or [None])[0]
    assert isinstance(argv0, str)
    assert Path(argv0).is_absolute()
    assert Path(argv0).name.startswith("python")
    assert argv0.startswith(("/bin/", "/usr/bin/", "/usr/local/bin/", "/opt/hostedtoolcache/"))
    assert (run_dir / "exec" / "stdout.txt").exists()
    assert (run_dir / "exec" / "stderr.txt").exists()
    assert (run_dir / "out" / "abs_argv0.json").exists()


def test_controlled_path_is_shared_and_posix_only() -> None:
    code = (
        "from llmfuzz.command_allowlist import CONTROLLED_PATH\n"
        "assert '/opt/homebrew/bin' not in CONTROLLED_PATH\n"
        "assert '/opt/hostedtoolcache' not in CONTROLLED_PATH\n"
        "import llmfuzz.exec_engine_v1 as ee\n"
        "import llmfuzz.spec as sp\n"
        "assert ee._CONTROLLED_PATH == CONTROLLED_PATH\n"
        "assert sp._CONTROLLED_PATH == CONTROLLED_PATH\n"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code],
        cwd=str(_REPO_ROOT),
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, f"controlled-path invariant failed:\n{proc.stdout}\n{proc.stderr}\n"


def test_cli_version_flag() -> None:
    proc = _run_llmfuzz("--version")
    assert proc.returncode == 0
    out = (proc.stdout or "").strip()
    assert out and _SEMVER_RE.search(out), f"unexpected --version output: {out!r}"


def test_validate_pythonunbuffered_contract(tmp_path: Path) -> None:
    work_root_base = tmp_path / "work_root"
    seed_path = tmp_path / "seed.bin"
    seed_path.write_bytes(b"seed")

    base = {
        "schema_version": "llmfuzz.fuzzspec.v1",
        "campaign_id": "camp_validate_env",
        "target": {
            "agent_id": "agent",
            "work_root_base": str(work_root_base),
            "command": [str(Path(sys.executable).resolve()), "-c", "print('ok')"],
        },
        "seed": {"path": str(seed_path)},
        "mutations": {"cases": 1},
        "outputs": {"out_dir": "runs/<run_id>/out", "eval_dir": "runs/<run_id>/eval"},
    }

    bad = dict(base)
    bad["execution"] = {"env_overrides": {"PYTHONUNBUFFERED": "true"}}
    bad_path = tmp_path / "spec_bad.json"
    bad_path.write_text(json.dumps(bad, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    bad_proc = _run_llmfuzz("validate", "--spec", str(bad_path))
    assert bad_proc.returncode != 0

    good = dict(base)
    good["execution"] = {"env_overrides": {"PYTHONUNBUFFERED": "1"}}
    good_path = tmp_path / "spec_good.json"
    good_path.write_text(json.dumps(good, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    good_proc = _run_llmfuzz("validate", "--spec", str(good_path))
    assert good_proc.returncode == 0


def test_validator_accepts_hostedtoolcache_abs_exec_when_present(tmp_path: Path) -> None:
    exe = Path(sys.executable).resolve()
    hosted_root = Path("/opt/hostedtoolcache")
    if not hosted_root.exists():
        pytest.skip("/opt/hostedtoolcache not present")
    try:
        exe.relative_to(hosted_root)
    except ValueError:
        pytest.skip("sys.executable not under /opt/hostedtoolcache")
    if not exe.exists():
        pytest.skip("hostedtoolcache executable does not exist")

    work_root_base = tmp_path / "work_root"
    seed_path = tmp_path / "seed.bin"
    seed_path.write_bytes(b"seed")

    spec = {
        "schema_version": "llmfuzz.fuzzspec.v1",
        "campaign_id": "camp_hostedtoolcache_abs",
        "target": {
            "agent_id": "agent",
            "work_root_base": str(work_root_base),
            "command": [str(exe), "-c", "print('ok')"],
        },
        "seed": {"path": str(seed_path)},
        "mutations": {"cases": 1},
        "execution": {},
        "outputs": {"out_dir": "runs/<run_id>/out", "eval_dir": "runs/<run_id>/eval"},
    }
    spec_path = tmp_path / "spec_hostedtoolcache_abs.json"
    spec_path.write_text(json.dumps(spec, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    code = (
        "import json\n"
        "from pathlib import Path\n"
        "from llmfuzz.spec import validate_spec\n"
        f"raw = json.loads(Path({json.dumps(str(spec_path))}).read_text(encoding='utf-8'))\n"
        "validate_spec(raw)\n"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code],
        cwd=str(_REPO_ROOT),
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, f"hostedtoolcache abs exec not accepted:\n{proc.stdout}\n{proc.stderr}\n"

