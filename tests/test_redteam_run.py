from __future__ import annotations

import json
import os
import socket
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

import llmfuzz.cli as cli
import llmfuzz.redteam_run as redteam_run
from llmfuzz.redteam_contracts import canonical_contract_bytes, target_input_from_case
from llmfuzz.redteam_corpus import (
    ACCEPTED_CORPUS_SHA256,
    canonical_persisted_bytes,
    load_bundled_accepted_corpus,
    validate_corpus,
)
from llmfuzz.redteam_demo_target import (
    FIXED_POLICY,
    FIXED_TARGET_ID,
    MAX_TARGET_OUTPUT_BYTES,
    VULNERABLE_POLICY,
    VULNERABLE_TARGET_ID,
    DemoTargetValidationError,
    canonical_target_output_bytes,
    execute_demo_target,
    load_target_input_bytes,
    load_target_output_bytes,
    target_output_for,
    validate_target_output,
)
from llmfuzz.redteam_run import (
    ACCEPTED_PERSISTED_SHA256,
    CORPUS_REFERENCE_SCHEMA_VERSION,
    EXECUTION_SCHEMA_VERSION,
    EXECUTION_STATUSES,
    MAX_TARGET_STDERR_BYTES,
    RUN_MANIFEST_SCHEMA_VERSION,
    TARGET_TIMEOUT_SECONDS,
    BoundedProcessResult,
    RedTeamRunResult,
    RedTeamRunValidationError,
    canonical_run_cli_output,
    load_accepted_corpus,
    run_accepted_corpus,
    run_bounded_process,
    target_command,
)


_REPOSITORY = Path(__file__).resolve().parents[1]


def _process(
    tmp_path: Path,
    code: str,
    *,
    timeout_seconds: float = 2.0,
    stdout_limit: int = MAX_TARGET_OUTPUT_BYTES,
    stderr_limit: int = MAX_TARGET_STDERR_BYTES,
) -> BoundedProcessResult:
    return run_bounded_process(
        [sys.executable, "-c", code],
        stdin_bytes=b"",
        cwd=tmp_path,
        env={"PYTHONDONTWRITEBYTECODE": "1"},
        timeout_seconds=timeout_seconds,
        stdout_limit=stdout_limit,
        stderr_limit=stderr_limit,
    )


def _assert_process_gone(pid: int) -> None:
    deadline = time.monotonic() + 2.0
    process_path = Path(f"/proc/{pid}")
    while process_path.exists() and time.monotonic() < deadline:
        time.sleep(0.02)
    assert not process_path.exists()


def _fake_process(policy: object):
    def execute(
        argv: object,
        *,
        stdin_bytes: bytes,
        **_kwargs: object,
    ) -> BoundedProcessResult:
        target_input = load_target_input_bytes(stdin_bytes)
        output = canonical_target_output_bytes(target_output_for(target_input, policy))
        return BoundedProcessResult(
            tuple(argv),  # type: ignore[arg-type]
            "completed",
            0,
            output,
            b"",
            False,
            False,
            False,
            None,
        )

    return execute


def _manifest(root: Path) -> dict[str, object]:
    return json.loads((root / "llmfuzz" / "redteam-run.json").read_bytes())


def _case_records(manifest: dict[str, object]) -> list[dict[str, object]]:
    records = manifest["cases"]
    assert isinstance(records, list)
    assert all(isinstance(record, dict) for record in records)
    return records  # type: ignore[return-value]


def _actual_cli(
    target: str,
    output: Path,
    *,
    corpus: Path | None = None,
    environment: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    argv = [
        sys.executable,
        "-m",
        "llmfuzz",
        "redteam",
        "run",
        "--target",
        target,
        "--output",
        str(output),
    ]
    if corpus is not None:
        argv.extend(("--corpus", str(corpus)))
    env = {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPATH": str(_REPOSITORY),
    }
    if environment:
        env.update(environment)
    return subprocess.run(
        argv,
        cwd=_REPOSITORY,
        env=env,
        capture_output=True,
        check=False,
        shell=False,
    )


def _semantic_files(root: Path) -> dict[str, bytes]:
    manifest = _manifest(root)
    paths = {"llmfuzz/redteam-run.json"}
    for record in _case_records(manifest):
        for field in (
            "corpus_reference_path",
            "target_input_path",
            "events_path",
        ):
            value = record[field]
            if isinstance(value, str):
                paths.add(value)
    return {path: (root / path).read_bytes() for path in sorted(paths)}


def test_d1b_public_literals_and_fixed_command_are_locked() -> None:
    executable = Path(sys.executable).resolve()
    argv = target_command("fixed")

    assert ACCEPTED_PERSISTED_SHA256 == (
        "15d5a23bcd87cdf7c12a7557bf2c8d738199f5dd2a5c393c94d49462f412b461"
    )
    assert CORPUS_REFERENCE_SCHEMA_VERSION == "llmfuzz.redteam.corpus-reference.v1"
    assert EXECUTION_SCHEMA_VERSION == "llmfuzz.redteam.execution.v1"
    assert RUN_MANIFEST_SCHEMA_VERSION == "llmfuzz.redteam.run.v1"
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
    assert MAX_TARGET_STDERR_BYTES == 1_024
    assert TARGET_TIMEOUT_SECONDS == 5.0
    assert argv == (
        str(executable),
        "-m",
        "llmfuzz.redteam_target",
        "--target",
        "fixed",
    )
    assert stat.S_ISREG(executable.stat().st_mode)
    assert os.access(executable, os.X_OK)


@pytest.mark.parametrize("mode", (0o755, 0o775))
def test_trusted_python_executable_accepts_regular_executable_modes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: int,
) -> None:
    executable = tmp_path / "python"
    executable.write_bytes(b"synthetic executable")
    executable.chmod(mode)
    monkeypatch.setattr(sys, "executable", str(executable))

    assert redteam_run._trusted_python_executable() == executable.resolve(strict=True)


def test_trusted_python_executable_rejects_world_writable_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "python"
    executable.write_bytes(b"synthetic executable")
    executable.chmod(0o777)
    monkeypatch.setattr(sys, "executable", str(executable))

    with pytest.raises(RedTeamRunValidationError) as exc_info:
        redteam_run._trusted_python_executable()

    assert exc_info.value.code == "executable_invalid"
    assert str(executable) not in str(exc_info.value)


def test_trusted_python_executable_rejects_non_executable_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "python"
    executable.write_bytes(b"synthetic executable")
    executable.chmod(0o644)
    monkeypatch.setattr(sys, "executable", str(executable))

    with pytest.raises(RedTeamRunValidationError) as exc_info:
        redteam_run._trusted_python_executable()

    assert exc_info.value.code == "executable_invalid"


def test_trusted_python_executable_rejects_non_regular_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "python"
    executable.mkdir(mode=0o755)
    monkeypatch.setattr(sys, "executable", str(executable))

    with pytest.raises(RedTeamRunValidationError) as exc_info:
        redteam_run._trusted_python_executable()

    assert exc_info.value.code == "executable_invalid"


def test_trusted_python_executable_sanitizes_resolution_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "missing-python"
    monkeypatch.setattr(sys, "executable", str(executable))

    with pytest.raises(RedTeamRunValidationError) as exc_info:
        redteam_run._trusted_python_executable()

    assert exc_info.value.code == "executable_invalid"
    assert str(executable) not in str(exc_info.value)
    assert exc_info.value.__cause__ is None


def test_trusted_python_executable_sanitizes_stat_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "python"
    executable.write_bytes(b"synthetic executable")
    executable.chmod(0o755)
    resolved = executable.resolve(strict=True)
    original_stat = Path.stat

    def fail_selected_stat(path: Path, *args: object, **kwargs: object) -> os.stat_result:
        if path == resolved:
            raise OSError("nested sensitive failure")
        return original_stat(path, *args, **kwargs)

    monkeypatch.setattr(sys, "executable", str(executable))
    monkeypatch.setattr(Path, "stat", fail_selected_stat)

    with pytest.raises(RedTeamRunValidationError) as exc_info:
        redteam_run._trusted_python_executable()

    assert exc_info.value.code == "executable_invalid"
    assert str(executable) not in str(exc_info.value)
    assert "nested sensitive failure" not in str(exc_info.value)
    assert exc_info.value.__cause__ is None


@pytest.mark.parametrize("target", ("fixed", "vulnerable"))
def test_target_command_retains_locked_argv_with_group_writable_interpreter(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target: str,
) -> None:
    executable = tmp_path / "python"
    executable.write_bytes(b"synthetic executable")
    executable.chmod(0o775)
    resolved = executable.resolve(strict=True)
    monkeypatch.setattr(sys, "executable", str(executable))

    assert target_command(target) == (
        str(resolved),
        "-m",
        "llmfuzz.redteam_target",
        "--target",
        target,
    )


def test_target_child_environment_is_minimal_and_does_not_inherit_secrets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "synthetic-key")
    monkeypatch.setenv("HTTPS_PROXY", "http://synthetic-proxy")
    monkeypatch.setenv("ARBITRARY_OVERRIDE", "synthetic-value")

    environment = redteam_run._target_environment()

    assert set(environment) == {
        "PYTHONDONTWRITEBYTECODE",
        "PYTHONIOENCODING",
        "PYTHONPATH",
        "PYTHONUNBUFFERED",
    }
    assert environment["PYTHONUNBUFFERED"] == "1"
    assert environment["PYTHONIOENCODING"] == "utf-8"
    assert "OPENAI_API_KEY" not in environment
    assert "HTTPS_PROXY" not in environment
    assert "ARBITRARY_OVERRIDE" not in environment


@pytest.mark.parametrize(
    ("policy", "target_id"),
    (
        (VULNERABLE_POLICY, VULNERABLE_TARGET_ID),
        (FIXED_POLICY, FIXED_TARGET_ID),
    ),
)
def test_target_output_identity_binding_accepts_matching_identity(
    policy: object,
    target_id: str,
) -> None:
    target_input = target_input_from_case(load_bundled_accepted_corpus().cases[0])
    output = target_output_for(target_input, policy)
    raw = json.loads(canonical_target_output_bytes(output))

    assert (
        validate_target_output(
            raw,
            expected_input=target_input,
            expected_target_id=target_id,
        )
        == output
    )
    assert (
        load_target_output_bytes(
            canonical_target_output_bytes(output),
            expected_input=target_input,
            expected_target_id=target_id,
        )
        == output
    )


@pytest.mark.parametrize(
    ("policy", "expected_target_id"),
    (
        (VULNERABLE_POLICY, FIXED_TARGET_ID),
        (FIXED_POLICY, VULNERABLE_TARGET_ID),
    ),
)
def test_target_output_identity_binding_rejects_substitution(
    policy: object,
    expected_target_id: str,
) -> None:
    target_input = target_input_from_case(load_bundled_accepted_corpus().cases[0])
    output = canonical_target_output_bytes(target_output_for(target_input, policy))

    with pytest.raises(DemoTargetValidationError, match="expected target identity"):
        load_target_output_bytes(
            output,
            expected_input=target_input,
            expected_target_id=expected_target_id,
        )
    with pytest.raises(DemoTargetValidationError, match="locked demo-target identity"):
        load_target_output_bytes(
            output,
            expected_input=target_input,
            expected_target_id="unknown",
        )


@pytest.mark.parametrize(
    ("selected", "returned_policy"),
    (("vulnerable", FIXED_POLICY), ("fixed", VULNERABLE_POLICY)),
)
def test_identity_mismatch_persists_no_event_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    selected: str,
    returned_policy: object,
) -> None:
    monkeypatch.setattr(
        redteam_run,
        "run_bounded_process",
        _fake_process(returned_policy),
    )
    root = tmp_path / selected

    result = run_accepted_corpus(target=selected, output=root)

    assert result.completed is False
    records = _case_records(result.manifest)
    assert {record["status"] for record in records} == {"malformed_output"}
    assert all(record["events_path"] is None for record in records)
    assert list(root.glob("runs/*/exec/redteam-events.json")) == []
    assert len(list(root.glob("runs/*/exec/exec.json"))) == 16


def test_bounded_process_uses_argv_shell_false_and_new_session(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[object, dict[str, object]]] = []
    real_popen = subprocess.Popen

    def observed_popen(argv: object, **kwargs: object):
        calls.append((argv, kwargs))
        return real_popen(argv, **kwargs)

    monkeypatch.setattr(redteam_run.subprocess, "Popen", observed_popen)
    result = _process(tmp_path, "print('bounded')")

    assert result.status == "completed"
    assert result.stdout == b"bounded\n"
    assert len(calls) == 1
    argv, kwargs = calls[0]
    assert isinstance(argv, list)
    assert kwargs["shell"] is False
    assert kwargs["start_new_session"] is True
    assert kwargs["stdout"] is subprocess.PIPE
    assert kwargs["stderr"] is subprocess.PIPE


def test_selector_construction_failure_is_bounded_and_does_not_launch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    popen_calls: list[None] = []

    def fail_selector() -> object:
        raise OSError("synthetic selector failure")

    def forbidden_popen(*_args: object, **_kwargs: object) -> object:
        popen_calls.append(None)
        raise AssertionError("Popen must not be called")

    monkeypatch.setattr(redteam_run.selectors, "DefaultSelector", fail_selector)
    monkeypatch.setattr(redteam_run.subprocess, "Popen", forbidden_popen)

    result = run_bounded_process(
        ["synthetic-target"],
        stdin_bytes=b"",
        cwd=tmp_path,
        env={},
    )

    assert result.status == "launch_error"
    assert result.error_code == "process_io_error"
    assert result.exit_code is None
    assert result.stdout == b""
    assert result.stderr == b""
    assert popen_calls == []


def test_selector_is_closed_when_popen_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ObservableSelector:
        close_calls = 0

        def close(self) -> None:
            self.close_calls += 1

    selector = ObservableSelector()
    monkeypatch.setattr(
        redteam_run.selectors,
        "DefaultSelector",
        lambda: selector,
    )
    monkeypatch.setattr(
        redteam_run.subprocess,
        "Popen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            OSError("synthetic launch failure")
        ),
    )

    result = run_bounded_process(
        ["synthetic-target"],
        stdin_bytes=b"",
        cwd=tmp_path,
        env={},
    )

    assert selector.close_calls == 1
    assert result.status == "launch_error"
    assert result.error_code == "launch_error"
    assert result.stdout == b""
    assert result.stderr == b""


def test_selector_is_closed_when_popen_raises_memory_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selector_calls: list[None] = []
    selector_close_calls: list[None] = []

    class ObservableSelector:
        def close(self) -> None:
            selector_close_calls.append(None)

    selector = ObservableSelector()

    def observed_selector() -> object:
        selector_calls.append(None)
        return selector

    def fail_popen(*_args: object, **_kwargs: object) -> object:
        raise MemoryError("synthetic Popen allocation failure")

    monkeypatch.setattr(redteam_run.selectors, "DefaultSelector", observed_selector)
    monkeypatch.setattr(redteam_run.subprocess, "Popen", fail_popen)

    result = run_bounded_process(
        ["synthetic-target"],
        stdin_bytes=b"",
        cwd=tmp_path,
        env={},
    )

    assert selector_calls == [None]
    assert selector_close_calls == [None]
    assert result.status == "launch_error"
    assert result.error_code == "process_io_error"
    assert result.exit_code is None
    assert result.stdout == b""
    assert result.stderr == b""


def test_selector_is_closed_before_unexpected_popen_exception_escapes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selector_close_calls: list[None] = []

    class ObservableSelector:
        def close(self) -> None:
            selector_close_calls.append(None)

    monkeypatch.setattr(
        redteam_run.selectors,
        "DefaultSelector",
        ObservableSelector,
    )
    monkeypatch.setattr(
        redteam_run.subprocess,
        "Popen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            ValueError("synthetic unexpected Popen failure")
        ),
    )

    with pytest.raises(ValueError, match="synthetic unexpected Popen failure"):
        run_bounded_process(
            ["synthetic-target"],
            stdin_bytes=b"",
            cwd=tmp_path,
            env={},
        )

    assert selector_close_calls == [None]


def test_initial_buffer_allocation_failure_precedes_process_resources(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selector_calls: list[None] = []
    popen_calls: list[None] = []

    def fail_buffer_allocation() -> object:
        raise MemoryError("synthetic pre-launch allocation failure")

    def forbidden_selector() -> object:
        selector_calls.append(None)
        raise AssertionError("selector must not be constructed")

    def forbidden_popen(*_args: object, **_kwargs: object) -> object:
        popen_calls.append(None)
        raise AssertionError("Popen must not be called")

    monkeypatch.setattr(
        redteam_run,
        "bytearray",
        fail_buffer_allocation,
        raising=False,
    )
    monkeypatch.setattr(redteam_run.selectors, "DefaultSelector", forbidden_selector)
    monkeypatch.setattr(redteam_run.subprocess, "Popen", forbidden_popen)

    with pytest.raises(MemoryError, match="pre-launch allocation"):
        run_bounded_process(
            ["synthetic-target"],
            stdin_bytes=b"",
            cwd=tmp_path,
            env={},
        )

    assert selector_calls == []
    assert popen_calls == []


def test_first_guarded_post_launch_memory_error_reaps_and_closes_resources(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    processes: list[subprocess.Popen[bytes]] = []
    real_popen = subprocess.Popen
    selector = redteam_run.selectors.DefaultSelector()
    selector_closed: list[None] = []
    real_selector_close = selector.close

    class FirstOperationFailureProcess:
        def __init__(self, process: subprocess.Popen[bytes]) -> None:
            self._process = process

        @property
        def pid(self) -> int:
            raise MemoryError("synthetic first guarded operation failure")

        def __getattr__(self, name: str) -> object:
            return getattr(self._process, name)

    def observed_close() -> None:
        selector_closed.append(None)
        real_selector_close()

    def observed_popen(argv: object, **kwargs: object) -> object:
        process = real_popen(argv, **kwargs)
        processes.append(process)
        return FirstOperationFailureProcess(process)

    monkeypatch.setattr(selector, "close", observed_close)
    monkeypatch.setattr(redteam_run.selectors, "DefaultSelector", lambda: selector)
    monkeypatch.setattr(redteam_run.subprocess, "Popen", observed_popen)

    result = _process(tmp_path, "import time; time.sleep(60)")

    assert result.status == "launch_error"
    assert result.error_code == "process_io_error"
    assert result.stdout == b""
    assert result.stderr == b""
    assert len(processes) == 1
    process = processes[0]
    assert process.poll() is not None
    _assert_process_gone(process.pid)
    assert process.stdin is not None and process.stdin.closed
    assert process.stdout is not None and process.stdout.closed
    assert process.stderr is not None and process.stderr.closed
    assert selector_closed == [None]


@pytest.mark.parametrize(
    ("channel", "count", "expected_status"),
    (
        (1, MAX_TARGET_OUTPUT_BYTES, "completed"),
        (1, MAX_TARGET_OUTPUT_BYTES + 1, "stdout_limit"),
        (2, MAX_TARGET_STDERR_BYTES, "completed"),
        (2, MAX_TARGET_STDERR_BYTES + 1, "stderr_limit"),
    ),
)
def test_bounded_process_enforces_exact_output_limits_while_running(
    tmp_path: Path,
    channel: int,
    count: int,
    expected_status: str,
) -> None:
    result = _process(tmp_path, f"import os; os.write({channel}, b'x' * {count})")

    assert result.status == expected_status
    if channel == 1:
        assert len(result.stdout) == min(count, MAX_TARGET_OUTPUT_BYTES)
        assert result.stdout_limit_exceeded is (count > MAX_TARGET_OUTPUT_BYTES)
        assert len(result.stderr) == 0
    else:
        assert len(result.stderr) == min(count, MAX_TARGET_STDERR_BYTES)
        assert result.stderr_limit_exceeded is (count > MAX_TARGET_STDERR_BYTES)
        assert len(result.stdout) == 0


def test_bounded_process_normalizes_timeout_nonzero_and_launch_failure(
    tmp_path: Path,
) -> None:
    timed_out = _process(
        tmp_path,
        "import time; time.sleep(60)",
        timeout_seconds=0.1,
    )
    nonzero = _process(tmp_path, "raise SystemExit(7)")
    launch = run_bounded_process(
        [str(tmp_path / "missing-executable")],
        stdin_bytes=b"",
        cwd=tmp_path,
        env={},
        timeout_seconds=0.1,
    )

    assert timed_out.status == "timeout"
    assert timed_out.timed_out is True
    assert nonzero.status == "nonzero_exit"
    assert nonzero.exit_code == 7
    assert launch.status == "launch_error"
    assert launch.exit_code is None
    for result in (timed_out, nonzero, launch):
        assert len(result.stdout) <= MAX_TARGET_OUTPUT_BYTES
        assert len(result.stderr) <= MAX_TARGET_STDERR_BYTES


def test_timeout_terminates_and_reaps_spawned_process_group(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent_pids: list[int] = []
    real_popen = subprocess.Popen

    def observed_popen(argv: object, **kwargs: object):
        process = real_popen(argv, **kwargs)
        parent_pids.append(process.pid)
        return process

    monkeypatch.setattr(redteam_run.subprocess, "Popen", observed_popen)
    code = (
        "import subprocess,sys,time\n"
        "child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'])\n"
        "print(child.pid,flush=True)\n"
        "time.sleep(60)\n"
    )
    result = _process(tmp_path, code, timeout_seconds=0.2)
    child_pid = int(result.stdout.strip())

    assert result.status == "timeout"
    assert len(parent_pids) == 1
    _assert_process_gone(parent_pids[0])
    _assert_process_gone(child_pid)


@pytest.mark.parametrize(
    ("channel", "limit", "expected_status"),
    (
        (1, MAX_TARGET_OUTPUT_BYTES, "stdout_limit"),
        (2, MAX_TARGET_STDERR_BYTES, "stderr_limit"),
    ),
)
def test_output_overflow_reaps_same_session_descendant(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    channel: int,
    limit: int,
    expected_status: str,
) -> None:
    parent_pids: list[int] = []
    real_popen = subprocess.Popen

    def observed_popen(argv: object, **kwargs: object):
        process = real_popen(argv, **kwargs)
        parent_pids.append(process.pid)
        return process

    monkeypatch.setattr(redteam_run.subprocess, "Popen", observed_popen)
    code = (
        "import os,subprocess,sys,time\n"
        "child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'])\n"
        f"os.write({channel},str(child.pid).encode()+b'\\n'+b'x'*{limit + 1})\n"
        "time.sleep(60)\n"
    )
    result = _process(tmp_path, code)
    evidence = result.stdout if channel == 1 else result.stderr
    child_pid = int(evidence.splitlines()[0])

    assert result.status == expected_status
    assert len(parent_pids) == 1
    _assert_process_gone(parent_pids[0])
    _assert_process_gone(child_pid)


def test_normal_parent_exit_reaps_same_session_descendant(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent_pids: list[int] = []
    real_popen = subprocess.Popen

    def observed_popen(argv: object, **kwargs: object):
        process = real_popen(argv, **kwargs)
        parent_pids.append(process.pid)
        return process

    monkeypatch.setattr(redteam_run.subprocess, "Popen", observed_popen)
    code = (
        "import subprocess,sys\n"
        "child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'],"
        "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n"
        "print(child.pid,flush=True)\n"
    )
    result = _process(tmp_path, code)
    child_pid = int(result.stdout.strip())

    assert result.status == "completed"
    assert len(parent_pids) == 1
    _assert_process_gone(parent_pids[0])
    _assert_process_gone(child_pid)


def test_post_launch_process_io_failure_reaps_process_group(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    descendant_path = tmp_path / "descendant.pid"
    parent_pids: list[int] = []
    real_popen = subprocess.Popen

    def observed_popen(argv: object, **kwargs: object):
        process = real_popen(argv, **kwargs)
        parent_pids.append(process.pid)
        return process

    def fail_after_descendant_started(_fd: int, _blocking: bool) -> None:
        deadline = time.monotonic() + 2.0
        while not descendant_path.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        if not descendant_path.exists():
            raise AssertionError("descendant did not start")
        raise OSError("synthetic process I/O failure")

    monkeypatch.setattr(redteam_run.subprocess, "Popen", observed_popen)
    monkeypatch.setattr(redteam_run.os, "set_blocking", fail_after_descendant_started)
    code = (
        "import pathlib,subprocess,sys,time\n"
        "child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'])\n"
        f"pathlib.Path({str(descendant_path)!r}).write_text(str(child.pid))\n"
        "time.sleep(60)\n"
    )

    result = _process(tmp_path, code)
    descendant_pid = int(descendant_path.read_text(encoding="utf-8"))

    assert result.status == "launch_error"
    assert result.error_code == "process_io_error"
    assert result.stdout == b""
    assert result.stderr == b""
    assert len(parent_pids) == 1
    _assert_process_gone(parent_pids[0])
    _assert_process_gone(descendant_pid)


def test_post_launch_memory_error_reaps_process_group(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    descendant_path = tmp_path / "descendant.pid"
    parent_pids: list[int] = []
    real_popen = subprocess.Popen

    class FailingBuffer(bytearray):
        def extend(self, _data: object) -> None:
            raise MemoryError("synthetic bounded-buffer failure")

    def observed_popen(argv: object, **kwargs: object):
        process = real_popen(argv, **kwargs)
        parent_pids.append(process.pid)
        return process

    monkeypatch.setattr(redteam_run, "bytearray", FailingBuffer, raising=False)
    monkeypatch.setattr(redteam_run.subprocess, "Popen", observed_popen)
    code = (
        "import os,pathlib,subprocess,sys,time\n"
        "child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'])\n"
        f"pathlib.Path({str(descendant_path)!r}).write_text(str(child.pid))\n"
        "os.write(1,b'x')\n"
        "time.sleep(60)\n"
    )

    result = _process(tmp_path, code)
    descendant_pid = int(descendant_path.read_text(encoding="utf-8"))

    assert result.status == "launch_error"
    assert result.error_code == "process_io_error"
    assert len(result.stdout) <= MAX_TARGET_OUTPUT_BYTES
    assert len(result.stderr) <= MAX_TARGET_STDERR_BYTES
    assert len(parent_pids) == 1
    _assert_process_gone(parent_pids[0])
    _assert_process_gone(descendant_pid)


def test_bundled_and_exact_explicit_accepted_corpus_are_identical(
    tmp_path: Path,
) -> None:
    bundled = load_accepted_corpus()
    explicit_path = tmp_path / "accepted.json"
    explicit_path.write_bytes(bundled.persisted_bytes)
    explicit = load_accepted_corpus(explicit_path)

    assert bundled == explicit
    assert bundled.corpus.corpus_sha256 == ACCEPTED_CORPUS_SHA256
    assert bundled.persisted_sha256 == ACCEPTED_PERSISTED_SHA256
    assert bundled.persisted_bytes == canonical_persisted_bytes(bundled.corpus)
    assert len(bundled.corpus.cases) == 16


@pytest.mark.parametrize("kind", ("tampered", "other_valid"))
def test_nonaccepted_corpus_is_rejected_before_output_or_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
) -> None:
    accepted = load_accepted_corpus()
    corpus_path = tmp_path / "candidate.json"
    if kind == "tampered":
        data = bytearray(accepted.persisted_bytes)
        data[-2] ^= 1
        corpus_path.write_bytes(data)
    else:
        raw = json.loads(accepted.persisted_bytes)
        raw.pop("corpus_sha256")
        raw["cases"][0]["input"] += " changed"
        corpus_path.write_bytes(canonical_persisted_bytes(validate_corpus(raw)))
    calls: list[None] = []

    def forbidden(*_args: object, **_kwargs: object) -> object:
        calls.append(None)
        raise AssertionError("executor must not run")

    monkeypatch.setattr(redteam_run, "run_bounded_process", forbidden)
    output = tmp_path / "output"

    with pytest.raises(RedTeamRunValidationError, match="corpus validation failed"):
        run_accepted_corpus(
            target="fixed",
            output=output,
            corpus_path=corpus_path,
        )
    assert calls == []
    assert not output.exists()


@pytest.mark.parametrize("kind", ("file", "directory", "symlink"))
def test_existing_output_destination_is_rejected(
    tmp_path: Path,
    kind: str,
) -> None:
    output = tmp_path / "output"
    if kind == "file":
        output.write_text("existing", encoding="utf-8")
    elif kind == "directory":
        output.mkdir()
    else:
        output.symlink_to(tmp_path / "missing")

    with pytest.raises(RedTeamRunValidationError, match="already exists"):
        run_accepted_corpus(target="fixed", output=output)


def test_output_path_rejects_nul_traversal_and_symlinked_parent(
    tmp_path: Path,
) -> None:
    real_parent = tmp_path / "real"
    real_parent.mkdir()
    linked_parent = tmp_path / "linked"
    linked_parent.symlink_to(real_parent, target_is_directory=True)

    for output in (
        "bad\0path",
        str(tmp_path / "parent" / ".." / "output"),
        str(linked_parent / "output"),
    ):
        with pytest.raises(RedTeamRunValidationError, match="destination is invalid"):
            run_accepted_corpus(target="fixed", output=output)
    assert list(real_parent.iterdir()) == []


def test_new_root_no_overwrite_and_relative_artifact_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        redteam_run,
        "run_bounded_process",
        _fake_process(FIXED_POLICY),
    )
    overwrite_values: list[bool] = []
    real_atomic_write = redteam_run.atomic_write_bytes

    def observed_write(
        path: object,
        data: bytes,
        *,
        overwrite: bool = True,
    ) -> None:
        overwrite_values.append(overwrite)
        real_atomic_write(path, data, overwrite=overwrite)

    monkeypatch.setattr(redteam_run, "atomic_write_bytes", observed_write)
    root = tmp_path / "new-output"
    result = run_accepted_corpus(target="fixed", output=root)

    assert result.completed is True
    assert overwrite_values and set(overwrite_values) == {False}
    for record in _case_records(result.manifest):
        for key, value in record.items():
            if key.endswith("_path") and isinstance(value, str):
                path = Path(value)
                assert not path.is_absolute()
                assert ".." not in path.parts
                assert (root / path).is_file() or (root / path).is_dir()
    with pytest.raises(RedTeamRunValidationError, match="already exists"):
        run_accepted_corpus(target="fixed", output=root)


def test_single_case_persistence_uses_locked_bytes_and_no_eval(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    accepted = load_accepted_corpus()
    root = tmp_path / "single"
    root.mkdir()
    (root / "runs").mkdir()
    monkeypatch.setattr(
        redteam_run,
        "run_bounded_process",
        _fake_process(VULNERABLE_POLICY),
    )
    case = accepted.corpus.cases[0]
    record = redteam_run._case_execution(
        root=root,
        corpus_reference=redteam_run._corpus_reference_bytes(accepted),
        case=case,
        target_id=VULNERABLE_TARGET_ID,
        execution_id=redteam_run._execution_identity(
            accepted.corpus.corpus_sha256,
            VULNERABLE_TARGET_ID,
        ),
        argv=target_command("vulnerable"),
    )

    assert (root / str(record["target_input_path"])).read_bytes() == canonical_contract_bytes(
        target_input_from_case(case)
    )
    assert (root / str(record["events_path"])).read_bytes() == (
        root / str(record["stdout_path"])
    ).read_bytes()
    assert list(root.rglob("eval")) == []
    assert list(root.rglob("redteam-case-result.json")) == []


def test_process_failure_persists_bounded_execution_evidence_without_events(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def nonzero(argv: object, **_kwargs: object) -> BoundedProcessResult:
        return BoundedProcessResult(
            tuple(argv),  # type: ignore[arg-type]
            "nonzero_exit",
            9,
            b"bounded-output",
            b"bounded-error",
            False,
            False,
            False,
            "nonzero_exit",
        )

    monkeypatch.setattr(redteam_run, "run_bounded_process", nonzero)
    root = tmp_path / "failed"
    result = run_accepted_corpus(target="fixed", output=root)

    assert result.completed is False
    for record in _case_records(result.manifest):
        assert record["status"] == "nonzero_exit"
        assert record["events_path"] is None
        assert (root / str(record["stdout_path"])).read_bytes() == b"bounded-output"
        assert (root / str(record["stderr_path"])).read_bytes() == b"bounded-error"
        execution = json.loads((root / str(record["exec_path"])).read_bytes())
        assert execution["status"] == "nonzero_exit"
        assert execution["events_path"] is None
    assert list(root.glob("runs/*/exec/redteam-events.json")) == []


def test_selector_failure_persists_all_bounded_execution_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_selector() -> object:
        raise OSError("synthetic selector failure")

    def forbidden_popen(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("Popen must not be called")

    monkeypatch.setattr(redteam_run.selectors, "DefaultSelector", fail_selector)
    monkeypatch.setattr(redteam_run.subprocess, "Popen", forbidden_popen)
    root = tmp_path / "selector-failed"

    result = run_accepted_corpus(target="fixed", output=root)

    assert result.completed is False
    manifest_bytes = (root / "llmfuzz" / "redteam-run.json").read_bytes()
    assert manifest_bytes == (
        json.dumps(result.manifest, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    records = _case_records(result.manifest)
    assert len(records) == 16
    assert {record["status"] for record in records} == {"launch_error"}
    for record in records:
        assert record["events_path"] is None
        stdout = (root / str(record["stdout_path"])).read_bytes()
        stderr = (root / str(record["stderr_path"])).read_bytes()
        assert stdout == b""
        assert stderr == b""
        assert len(stdout) <= MAX_TARGET_OUTPUT_BYTES
        assert len(stderr) <= MAX_TARGET_STDERR_BYTES
        exec_bytes = (root / str(record["exec_path"])).read_bytes()
        execution = json.loads(exec_bytes)
        assert exec_bytes == (
            json.dumps(execution, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        assert execution["status"] == "launch_error"
        assert execution["error_code"] == "process_io_error"
        assert execution["events_path"] is None
        assert "verdict" not in execution
        assert "invariant_results" not in execution
    assert list(root.glob("runs/*/exec/redteam-events.json")) == []
    assert list(root.rglob("eval")) == []


def test_post_launch_memory_error_persists_all_bounded_execution_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_process_io(_fd: int, _blocking: bool) -> None:
        raise MemoryError("synthetic post-launch process I/O failure")

    monkeypatch.setattr(redteam_run.os, "set_blocking", fail_process_io)
    root = tmp_path / "memory-failed"

    result = run_accepted_corpus(target="fixed", output=root)

    assert result.completed is False
    manifest_bytes = (root / "llmfuzz" / "redteam-run.json").read_bytes()
    assert manifest_bytes == (
        json.dumps(result.manifest, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    records = _case_records(result.manifest)
    assert len(records) == 16
    assert {record["status"] for record in records} == {"launch_error"}
    assert "verdict" not in result.manifest
    for record in records:
        assert record["events_path"] is None
        stdout = (root / str(record["stdout_path"])).read_bytes()
        stderr = (root / str(record["stderr_path"])).read_bytes()
        assert len(stdout) <= MAX_TARGET_OUTPUT_BYTES
        assert len(stderr) <= MAX_TARGET_STDERR_BYTES
        exec_bytes = (root / str(record["exec_path"])).read_bytes()
        execution = json.loads(exec_bytes)
        assert exec_bytes == (
            json.dumps(execution, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        assert execution["status"] == "launch_error"
        assert execution["error_code"] == "process_io_error"
        assert execution["events_path"] is None
        assert "verdict" not in execution
        assert "invariant_results" not in execution
    assert list(root.glob("runs/*/exec/redteam-events.json")) == []
    assert list(root.rglob("eval")) == []
    assert list(root.rglob("redteam-case-result.json")) == []
    assert list(root.rglob("redteam-summary.json")) == []


def test_popen_memory_error_persists_all_bounded_execution_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_popen(*_args: object, **_kwargs: object) -> object:
        raise MemoryError("synthetic Popen allocation failure")

    monkeypatch.setattr(redteam_run.subprocess, "Popen", fail_popen)
    root = tmp_path / "popen-memory-failed"

    result = run_accepted_corpus(target="fixed", output=root)

    assert result.completed is False
    records = _case_records(result.manifest)
    assert len(records) == 16
    assert {record["status"] for record in records} == {"launch_error"}
    for record in records:
        assert record["events_path"] is None
        stdout = (root / str(record["stdout_path"])).read_bytes()
        stderr = (root / str(record["stderr_path"])).read_bytes()
        assert stdout == b""
        assert stderr == b""
        assert len(stdout) <= MAX_TARGET_OUTPUT_BYTES
        assert len(stderr) <= MAX_TARGET_STDERR_BYTES
        execution = json.loads((root / str(record["exec_path"])).read_bytes())
        assert execution["status"] == "launch_error"
        assert execution["error_code"] == "process_io_error"
        assert execution["events_path"] is None
    assert list(root.glob("runs/*/exec/redteam-events.json")) == []


def test_full_accepted_corpus_vulnerable_and_fixed_artifacts(tmp_path: Path) -> None:
    corpus = load_bundled_accepted_corpus()
    vulnerable_root = tmp_path / "vulnerable"
    fixed_root = tmp_path / "fixed"
    vulnerable = run_accepted_corpus(target="vulnerable", output=vulnerable_root)
    fixed = run_accepted_corpus(target="fixed", output=fixed_root)

    assert vulnerable.completed is fixed.completed is True
    assert vulnerable.case_count == fixed.case_count == len(corpus.cases) == 16
    assert vulnerable.manifest["corpus_sha256"] == ACCEPTED_CORPUS_SHA256
    assert fixed.manifest["corpus_sha256"] == ACCEPTED_CORPUS_SHA256
    assert set(vulnerable.manifest) == set(fixed.manifest) == {
        "case_count",
        "cases",
        "corpus_sha256",
        "execution_id",
        "persisted_sha256",
        "schema_version",
        "target_id",
    }
    assert [
        record["case_id"] for record in _case_records(vulnerable.manifest)
    ] == [case.case_id for case in corpus.cases]
    vulnerable_records = {
        record["case_id"]: record for record in _case_records(vulnerable.manifest)
    }
    fixed_records = {
        record["case_id"]: record for record in _case_records(fixed.manifest)
    }
    reference_bytes: set[bytes] = set()

    for case in corpus.cases:
        target_input = target_input_from_case(case)
        vulnerable_record = vulnerable_records[case.case_id]
        fixed_record = fixed_records[case.case_id]
        vulnerable_input = (
            vulnerable_root / str(vulnerable_record["target_input_path"])
        ).read_bytes()
        fixed_input = (fixed_root / str(fixed_record["target_input_path"])).read_bytes()
        assert vulnerable_input == fixed_input == canonical_contract_bytes(target_input)

        for root, record, target_id, policy in (
            (vulnerable_root, vulnerable_record, VULNERABLE_TARGET_ID, VULNERABLE_POLICY),
            (fixed_root, fixed_record, FIXED_TARGET_ID, FIXED_POLICY),
        ):
            assert record["status"] == "completed"
            events_path = record["events_path"]
            assert isinstance(events_path, str)
            events_bytes = (root / events_path).read_bytes()
            output = load_target_output_bytes(
                events_bytes,
                expected_input=target_input,
                expected_target_id=target_id,
            )
            assert output.events == execute_demo_target(target_input, policy)
            assert output.events[-1].event_type == "final"
            assert sum(event.event_type == "final" for event in output.events) == 1
            assert events_bytes == (root / str(record["stdout_path"])).read_bytes()
            assert (root / str(record["stderr_path"])).read_bytes() == b""
            execution = json.loads((root / str(record["exec_path"])).read_bytes())
            assert set(execution) == {
                "argv",
                "case_id",
                "case_run_id",
                "error_code",
                "events_path",
                "exit_code",
                "schema_version",
                "status",
                "stderr_limit_exceeded",
                "stderr_path",
                "stdout_limit_exceeded",
                "stdout_path",
                "target_id",
                "timed_out",
                "timeout_seconds",
            }
            assert execution["schema_version"] == EXECUTION_SCHEMA_VERSION
            assert execution["status"] == "completed"
            assert "verdict" not in execution
            assert "invariant_results" not in execution
            reference_bytes.add(
                (root / str(record["corpus_reference_path"])).read_bytes()
            )

        if case.attack_class in ("forbidden tool use", "approval bypass"):
            fixed_output = load_target_output_bytes(
                (fixed_root / str(fixed_record["events_path"])).read_bytes(),
                expected_input=target_input,
                expected_target_id=FIXED_TARGET_ID,
            )
            assert dict(fixed_output.events[-1].payload) == {"disposition": "blocked"}
            assert fixed_record["status"] == "completed"

    assert len(reference_bytes) == 1
    reference = json.loads(next(iter(reference_bytes)))
    assert reference == {
        "case_count": 16,
        "corpus_schema_version": "llmfuzz.redteam.corpus.v1",
        "corpus_sha256": ACCEPTED_CORPUS_SHA256,
        "persisted_sha256": ACCEPTED_PERSISTED_SHA256,
        "schema_version": CORPUS_REFERENCE_SCHEMA_VERSION,
    }
    assert next(iter(reference_bytes)) == (
        json.dumps(reference, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    for root in (vulnerable_root, fixed_root):
        assert list(root.rglob("eval")) == []
        assert list(root.rglob("*signature*")) == []
        assert list(root.rglob("*cluster*")) == []
        assert list(root.rglob("*report*")) == []


@pytest.mark.parametrize("target", ("vulnerable", "fixed"))
def test_execution_identity_and_semantic_artifacts_are_root_independent(
    tmp_path: Path,
    target: str,
) -> None:
    first_root = tmp_path / f"{target}-one"
    second_root = tmp_path / f"{target}-two"
    first = run_accepted_corpus(target=target, output=first_root)
    second = run_accepted_corpus(target=target, output=second_root)

    assert first.execution_id == second.execution_id
    assert first.manifest == second.manifest
    assert _semantic_files(first_root) == _semantic_files(second_root)
    assert [
        record["case_run_id"] for record in _case_records(first.manifest)
    ] == [record["case_run_id"] for record in _case_records(second.manifest)]


def test_cli_actual_module_supports_default_and_explicit_corpus(tmp_path: Path) -> None:
    accepted = load_accepted_corpus()
    corpus_path = tmp_path / "accepted.json"
    corpus_path.write_bytes(accepted.persisted_bytes)
    fixed_root = tmp_path / "fixed"
    vulnerable_root = tmp_path / "vulnerable"

    fixed = _actual_cli("fixed", fixed_root)
    vulnerable = _actual_cli(
        "vulnerable",
        vulnerable_root,
        corpus=corpus_path,
    )

    for process, root, target_id in (
        (fixed, fixed_root, FIXED_TARGET_ID),
        (vulnerable, vulnerable_root, VULNERABLE_TARGET_ID),
    ):
        assert process.returncode == 0
        assert process.stderr == b""
        assert process.stdout.endswith(b"\n") and not process.stdout.endswith(b"\n\n")
        output = json.loads(process.stdout)
        assert output == {
            "case_count": 16,
            "execution_id": _manifest(root)["execution_id"],
            "manifest": "llmfuzz/redteam-run.json",
            "target_id": target_id,
        }
        assert process.stdout == (
            json.dumps(output, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("utf-8")


@pytest.mark.parametrize(
    "arguments",
    (
        ("redteam", "run", "--output", "unused"),
        ("redteam", "run", "--target", "fixed"),
        (
            "redteam",
            "run",
            "--target",
            "unknown",
            "--output",
            "unused",
        ),
    ),
)
def test_cli_requires_closed_target_and_output(arguments: tuple[str, ...]) -> None:
    process = subprocess.run(
        [sys.executable, "-m", "llmfuzz", *arguments],
        cwd=_REPOSITORY,
        env={
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPATH": str(_REPOSITORY),
        },
        capture_output=True,
        check=False,
    )

    assert process.returncode == 2
    assert process.stdout == b""


def test_cli_execution_failure_is_nonzero_and_does_not_generate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output_root = tmp_path / "output"
    manifest_path = output_root / "llmfuzz" / "redteam-run.json"
    result = RedTeamRunResult(
        output_root,
        manifest_path,
        "rt_" + "0" * 64,
        FIXED_TARGET_ID,
        16,
        False,
        {},
    )
    generation_calls: list[None] = []
    monkeypatch.setattr(cli, "run_accepted_corpus", lambda **_kwargs: result)
    monkeypatch.setattr(
        cli,
        "generate_and_persist_corpus",
        lambda **_kwargs: generation_calls.append(None),
    )

    with pytest.raises(SystemExit) as exc_info:
        cli.main(
            [
                "redteam",
                "run",
                "--target",
                "fixed",
                "--output",
                str(output_root),
            ]
        )

    captured = capsys.readouterr()
    assert exc_info.value.code == 1
    assert captured.out == ""
    assert captured.err == "redteam run: execution did not complete.\n"
    assert generation_calls == []


def test_cli_local_corpus_rejection_is_exit_two_before_output(tmp_path: Path) -> None:
    corpus = tmp_path / "tampered.json"
    corpus.write_bytes(b"not accepted\n")
    output = tmp_path / "output"
    process = _actual_cli("fixed", output, corpus=corpus)

    assert process.returncode == 2
    assert process.stdout == b""
    assert process.stderr == (
        b"redteam run: Accepted Red Team corpus validation failed.\n"
    )
    assert not output.exists()


def test_actual_cli_is_offline_and_ignores_openai_environment_and_secret_file(
    tmp_path: Path,
) -> None:
    guard = tmp_path / "guard"
    guard.mkdir()
    secret = tmp_path / "secret"
    marker = "synthetic-secret-marker"
    secret.write_text(marker, encoding="utf-8")
    (guard / "sitecustomize.py").write_text(
        """
import builtins
import io
import os
import socket
import subprocess

secret_path = os.environ["LLMFUZZ_TEST_SECRET_PATH"]
real_import = builtins.__import__
real_open = builtins.open
real_io_open = io.open
real_getitem = os._Environ.__getitem__
real_popen = subprocess.Popen
guard_dir = os.path.dirname(__file__)

def is_secret_path(file):
    try:
        return os.fspath(file) == secret_path
    except TypeError:
        return False

def guarded_import(name, *args, **kwargs):
    if name == "openai" or name.startswith("openai."):
        raise AssertionError("OpenAI import forbidden")
    return real_import(name, *args, **kwargs)

def guarded_open(file, *args, **kwargs):
    if is_secret_path(file):
        raise AssertionError("secret file access forbidden")
    return real_open(file, *args, **kwargs)

def guarded_io_open(file, *args, **kwargs):
    if is_secret_path(file):
        raise AssertionError("secret file access forbidden")
    return real_io_open(file, *args, **kwargs)

def guarded_getitem(self, key):
    if key == "OPENAI_API_KEY":
        raise AssertionError("OPENAI_API_KEY access forbidden")
    return real_getitem(self, key)

def blocked(*args, **kwargs):
    raise AssertionError("network and DNS forbidden")

def guarded_popen(*args, **kwargs):
    child_env = kwargs.get("env")
    if isinstance(child_env, dict):
        forbidden = {
            "OPENAI_API_KEY",
            "OPENAI_API_KEY_FILE",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
        }
        if forbidden.intersection(child_env):
            raise AssertionError("target child inherited forbidden environment")
        child_env = dict(child_env)
        child_env["LLMFUZZ_TEST_SECRET_PATH"] = secret_path
        child_env["OPENAI_API_KEY_FILE"] = secret_path
        child_env["PYTHONPATH"] = os.pathsep.join(
            (guard_dir, child_env.get("PYTHONPATH", ""))
        )
        kwargs["env"] = child_env
    return real_popen(*args, **kwargs)

builtins.__import__ = guarded_import
builtins.open = guarded_open
io.open = guarded_io_open
os._Environ.__getitem__ = guarded_getitem
socket.create_connection = blocked
socket.getaddrinfo = blocked
socket.socket.connect = blocked
subprocess.Popen = guarded_popen
""".lstrip(),
        encoding="utf-8",
    )
    base_environment = {
        "LLMFUZZ_TEST_SECRET_PATH": str(secret),
        "OPENAI_API_KEY_FILE": str(secret),
        "PYTHONPATH": os.pathsep.join((str(guard), str(_REPOSITORY))),
    }
    absent_root = tmp_path / "absent"
    present_root = tmp_path / "present"

    absent = _actual_cli("fixed", absent_root, environment=base_environment)
    present = _actual_cli(
        "fixed",
        present_root,
        environment={**base_environment, "OPENAI_API_KEY": "synthetic-present-key"},
    )

    assert absent.returncode == present.returncode == 0
    assert absent.stderr == present.stderr == b""
    assert absent.stdout == present.stdout
    assert _semantic_files(absent_root) == _semantic_files(present_root)
    for root in (absent_root, present_root):
        for path in root.rglob("*"):
            if path.is_file():
                data = path.read_bytes()
                assert marker.encode() not in data
                assert b"synthetic-present-key" not in data


def test_d1b_source_has_no_openai_network_or_private_runtime_dependency() -> None:
    source = (_REPOSITORY / "llmfuzz" / "redteam_run.py").read_text(
        encoding="utf-8"
    )

    assert "import openai" not in source.lower()
    assert "OPENAI_API_KEY" not in source
    assert "socket" not in source
    assert ".llmfuzz_public" not in source
    assert "shell=True" not in source


def test_canonical_cli_output_rejects_incomplete_result(tmp_path: Path) -> None:
    result = RedTeamRunResult(
        tmp_path,
        tmp_path / "manifest",
        "rt_" + "0" * 64,
        FIXED_TARGET_ID,
        16,
        False,
        {},
    )

    with pytest.raises(Exception, match="execution failed"):
        canonical_run_cli_output(result)


@pytest.fixture(autouse=True)
def _block_in_process_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def blocked(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("network access is forbidden in D1B tests")

    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    monkeypatch.setattr(socket.socket, "connect", blocked)
