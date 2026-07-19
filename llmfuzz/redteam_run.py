from __future__ import annotations

import hashlib
import hmac
import json
import os
import selectors
import signal
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Mapping, Sequence

from .io import atomic_write_bytes
from .redteam_contracts import canonical_contract_bytes, target_input_from_case
from .redteam_corpus import (
    ACCEPTED_CORPUS_SHA256,
    CORPUS_SCHEMA_VERSION,
    Corpus,
    CorpusCase,
    CorpusValidationError,
    canonical_persisted_bytes,
    load_bundled_accepted_corpus,
    load_corpus,
)
from .redteam_demo_target import (
    FIXED_TARGET_ID,
    MAX_TARGET_INPUT_BYTES,
    MAX_TARGET_OUTPUT_BYTES,
    VULNERABLE_TARGET_ID,
    DemoTargetValidationError,
    load_target_output_bytes,
)


ACCEPTED_PERSISTED_SHA256 = (
    "15d5a23bcd87cdf7c12a7557bf2c8d738199f5dd2a5c393c94d49462f412b461"
)
CORPUS_REFERENCE_SCHEMA_VERSION = "llmfuzz.redteam.corpus-reference.v1"
EXECUTION_SCHEMA_VERSION = "llmfuzz.redteam.execution.v1"
RUN_MANIFEST_SCHEMA_VERSION = "llmfuzz.redteam.run.v1"

EXECUTION_STATUSES = (
    "completed",
    "timeout",
    "stdout_limit",
    "stderr_limit",
    "nonzero_exit",
    "launch_error",
    "malformed_output",
    "blocked",
)
TARGET_NAMES = ("vulnerable", "fixed")

MAX_TARGET_STDERR_BYTES = 1_024
TARGET_TIMEOUT_SECONDS = 5.0
_READ_CHUNK_BYTES = 4_096
_PROCESS_TERMINATION_GRACE_SECONDS = 0.25
_MAX_ARTIFACT_REF_CHARS = 256
_BUNDLED_RESOURCE = ("data", "accepted-corpus.v1.json")
_TARGET_IDS = {
    "vulnerable": VULNERABLE_TARGET_ID,
    "fixed": FIXED_TARGET_ID,
}


class RedTeamRunValidationError(ValueError):
    _MESSAGES = {
        "corpus_rejected": "Accepted Red Team corpus validation failed.",
        "destination_invalid": "Red Team output destination is invalid.",
        "destination_exists": "Red Team output destination already exists.",
        "executable_invalid": "Red Team target executable is invalid.",
        "invalid_configuration": "Red Team run configuration is invalid.",
    }

    def __init__(self, code: str) -> None:
        self.code = code if code in self._MESSAGES else "invalid_configuration"
        super().__init__(self._MESSAGES[self.code])


class RedTeamRunError(RuntimeError):
    _MESSAGES = {
        "artifact_persistence_failed": "Red Team execution evidence persistence failed.",
        "execution_internal_error": "Red Team execution failed.",
    }

    def __init__(self, code: str) -> None:
        self.code = code if code in self._MESSAGES else "execution_internal_error"
        super().__init__(self._MESSAGES[self.code])


@dataclass(frozen=True)
class AcceptedCorpus:
    corpus: Corpus
    persisted_bytes: bytes
    persisted_sha256: str


@dataclass(frozen=True)
class BoundedProcessResult:
    argv: tuple[str, ...]
    status: str
    exit_code: int | None
    stdout: bytes
    stderr: bytes
    timed_out: bool
    stdout_limit_exceeded: bool
    stderr_limit_exceeded: bool
    error_code: str | None


@dataclass(frozen=True)
class RedTeamRunResult:
    output_root: Path
    manifest_path: Path
    execution_id: str
    target_id: str
    case_count: int
    completed: bool
    manifest: dict[str, object]


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


def _bundled_persisted_bytes() -> bytes:
    try:
        return resources.files("llmfuzz").joinpath(*_BUNDLED_RESOURCE).read_bytes()
    except (OSError, TypeError):
        raise RedTeamRunValidationError("corpus_rejected") from None


def _validated_accepted_corpus(
    corpus: Corpus,
    persisted_bytes: bytes,
    accepted_bytes: bytes,
) -> AcceptedCorpus:
    persisted_sha256 = hashlib.sha256(persisted_bytes).hexdigest()
    if not hmac.compare_digest(corpus.corpus_sha256, ACCEPTED_CORPUS_SHA256):
        raise RedTeamRunValidationError("corpus_rejected")
    if not hmac.compare_digest(persisted_sha256, ACCEPTED_PERSISTED_SHA256):
        raise RedTeamRunValidationError("corpus_rejected")
    if persisted_bytes != accepted_bytes:
        raise RedTeamRunValidationError("corpus_rejected")
    if persisted_bytes != canonical_persisted_bytes(corpus):
        raise RedTeamRunValidationError("corpus_rejected")
    return AcceptedCorpus(corpus, persisted_bytes, persisted_sha256)


def load_accepted_corpus(corpus_path: str | os.PathLike[str] | None = None) -> AcceptedCorpus:
    accepted_bytes = _bundled_persisted_bytes()
    if hashlib.sha256(accepted_bytes).hexdigest() != ACCEPTED_PERSISTED_SHA256:
        raise RedTeamRunValidationError("corpus_rejected")

    if corpus_path is None:
        try:
            corpus = load_bundled_accepted_corpus()
        except CorpusValidationError:
            raise RedTeamRunValidationError("corpus_rejected") from None
        return _validated_accepted_corpus(corpus, accepted_bytes, accepted_bytes)

    try:
        source_value = os.fspath(corpus_path)
    except TypeError:
        raise RedTeamRunValidationError("corpus_rejected") from None
    if not isinstance(source_value, str) or not source_value or "\0" in source_value:
        raise RedTeamRunValidationError("corpus_rejected")
    source = Path(source_value)
    try:
        source_stat = os.lstat(source)
        if stat.S_ISLNK(source_stat.st_mode) or not stat.S_ISREG(source_stat.st_mode):
            raise RedTeamRunValidationError("corpus_rejected")
        corpus = load_corpus(source)
        persisted_bytes = source.read_bytes()
    except RedTeamRunValidationError:
        raise
    except (CorpusValidationError, OSError, TypeError):
        raise RedTeamRunValidationError("corpus_rejected") from None
    return _validated_accepted_corpus(corpus, persisted_bytes, accepted_bytes)


def _validated_target_name(target: object) -> tuple[str, str]:
    if not isinstance(target, str) or target not in _TARGET_IDS:
        raise RedTeamRunValidationError("invalid_configuration")
    return target, _TARGET_IDS[target]


def _validated_output_root(value: str | os.PathLike[str]) -> Path:
    try:
        raw = os.fspath(value)
    except TypeError:
        raise RedTeamRunValidationError("destination_invalid") from None
    if not isinstance(raw, str) or not raw or "\0" in raw:
        raise RedTeamRunValidationError("destination_invalid")
    original = Path(raw)
    if ".." in original.parts:
        raise RedTeamRunValidationError("destination_invalid")
    destination = Path(os.path.abspath(raw))
    if os.path.lexists(destination):
        raise RedTeamRunValidationError("destination_exists")

    parent = destination.parent
    try:
        parent_stat = os.lstat(parent)
        if stat.S_ISLNK(parent_stat.st_mode) or not stat.S_ISDIR(parent_stat.st_mode):
            raise RedTeamRunValidationError("destination_invalid")
        for ancestor in parent.parents:
            ancestor_stat = os.lstat(ancestor)
            if stat.S_ISLNK(ancestor_stat.st_mode) or not stat.S_ISDIR(
                ancestor_stat.st_mode
            ):
                raise RedTeamRunValidationError("destination_invalid")
        mode = os.W_OK | os.X_OK
        writable = (
            os.access(parent, mode, effective_ids=True)
            if os.access in os.supports_effective_ids
            else os.access(parent, mode)
        )
        if writable is not True:
            raise RedTeamRunValidationError("destination_invalid")
    except RedTeamRunValidationError:
        raise
    except OSError:
        raise RedTeamRunValidationError("destination_invalid") from None
    return destination


def _trusted_python_executable() -> Path:
    try:
        executable = Path(sys.executable).resolve(strict=True)
        executable_stat = executable.stat()
    except (OSError, RuntimeError):
        raise RedTeamRunValidationError("executable_invalid") from None
    if not stat.S_ISREG(executable_stat.st_mode) or not os.access(executable, os.X_OK):
        raise RedTeamRunValidationError("executable_invalid")
    if executable_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise RedTeamRunValidationError("executable_invalid")
    return executable


def target_command(target: str) -> tuple[str, ...]:
    target_name, _target_id = _validated_target_name(target)
    trusted = _trusted_python_executable()
    return (
        str(trusted),
        "-m",
        "llmfuzz.redteam_target",
        "--target",
        target_name,
    )


def _target_environment() -> dict[str, str]:
    package_parent = Path(__file__).resolve().parents[1]
    return {
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONIOENCODING": "utf-8",
        "PYTHONPATH": str(package_parent),
        "PYTHONUNBUFFERED": "1",
    }


def _close_selector_stream(
    selector: selectors.BaseSelector,
    stream: object,
) -> None:
    try:
        selector.unregister(stream)
    except (KeyError, ValueError):
        pass
    try:
        stream.close()  # type: ignore[union-attr]
    except OSError:
        pass


def _signal_process_group(process_group: int, sig: int) -> None:
    try:
        os.killpg(process_group, sig)
    except (ProcessLookupError, PermissionError):
        pass


def _terminate_process_group(process: subprocess.Popen[bytes], process_group: int) -> None:
    _signal_process_group(process_group, signal.SIGTERM)
    try:
        process.wait(timeout=_PROCESS_TERMINATION_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        pass
    _signal_process_group(process_group, signal.SIGKILL)
    try:
        process.wait(timeout=_PROCESS_TERMINATION_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def run_bounded_process(
    argv: Sequence[str],
    *,
    stdin_bytes: bytes,
    cwd: Path,
    env: Mapping[str, str],
    timeout_seconds: float = TARGET_TIMEOUT_SECONDS,
    stdout_limit: int = MAX_TARGET_OUTPUT_BYTES,
    stderr_limit: int = MAX_TARGET_STDERR_BYTES,
) -> BoundedProcessResult:
    command = tuple(argv)
    if (
        not command
        or any(not isinstance(item, str) or not item for item in command)
        or not isinstance(stdin_bytes, bytes)
        or len(stdin_bytes) > MAX_TARGET_INPUT_BYTES
        or not isinstance(timeout_seconds, (int, float))
        or isinstance(timeout_seconds, bool)
        or timeout_seconds <= 0
        or not isinstance(stdout_limit, int)
        or isinstance(stdout_limit, bool)
        or stdout_limit < 1
        or not isinstance(stderr_limit, int)
        or isinstance(stderr_limit, bool)
        or stderr_limit < 1
    ):
        raise RedTeamRunValidationError("invalid_configuration")

    stdout = bytearray()
    stderr = bytearray()
    input_offset = 0
    boundary_status: str | None = None
    error_code: str | None = None
    process_group: int | None = None
    streams: tuple[object, ...] = ()
    normal_completion = False
    process_argv = list(command)
    process_cwd = str(cwd)
    process_env = dict(env)

    try:
        selector = selectors.DefaultSelector()
    except OSError:
        return BoundedProcessResult(
            command,
            "launch_error",
            None,
            b"",
            b"",
            False,
            False,
            False,
            "process_io_error",
        )

    process: subprocess.Popen[bytes] | None = None
    try:
        process = subprocess.Popen(
            process_argv,
            cwd=process_cwd,
            env=process_env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            start_new_session=True,
            close_fds=True,
            bufsize=0,
        )
    except OSError:
        return BoundedProcessResult(
            command,
            "launch_error",
            None,
            b"",
            b"",
            False,
            False,
            False,
            "launch_error",
        )
    except MemoryError:
        return BoundedProcessResult(
            command,
            "launch_error",
            None,
            b"",
            b"",
            False,
            False,
            False,
            "process_io_error",
        )
    finally:
        if process is None:
            try:
                selector.close()
            except OSError:
                pass

    try:
        process_group = process.pid
        deadline = time.monotonic() + float(timeout_seconds)
        streams = tuple(
            stream
            for stream in (process.stdin, process.stdout, process.stderr)
            if stream is not None
        )
        if len(streams) != 3:
            raise OSError("subprocess pipe setup failed")
        stdin_stream, stdout_stream, stderr_stream = streams
        for stream in streams:
            os.set_blocking(stream.fileno(), False)
        if stdin_bytes:
            selector.register(stdin_stream, selectors.EVENT_WRITE, "stdin")
        else:
            stdin_stream.close()
        selector.register(stdout_stream, selectors.EVENT_READ, "stdout")
        selector.register(stderr_stream, selectors.EVENT_READ, "stderr")

        while boundary_status is None:
            remaining_time = deadline - time.monotonic()
            if remaining_time <= 0:
                boundary_status = "timeout"
                error_code = "timeout"
                break
            if process.poll() is not None and not selector.get_map():
                break
            ready = selector.select(min(remaining_time, 0.1))
            for key, _mask in sorted(
                ready,
                key=lambda item: {"stdin": 0, "stdout": 1, "stderr": 2}[item[0].data],
            ):
                stream = key.fileobj
                channel = key.data
                if channel == "stdin":
                    try:
                        written = os.write(
                            key.fd,
                            stdin_bytes[
                                input_offset : input_offset + _READ_CHUNK_BYTES
                            ],
                        )
                        input_offset += written
                    except (BlockingIOError, InterruptedError):
                        continue
                    except BrokenPipeError:
                        input_offset = len(stdin_bytes)
                    if input_offset >= len(stdin_bytes):
                        _close_selector_stream(selector, stream)
                    continue

                buffer = stdout if channel == "stdout" else stderr
                limit = stdout_limit if channel == "stdout" else stderr_limit
                available = limit - len(buffer)
                read_size = min(_READ_CHUNK_BYTES, available) if available else 1
                try:
                    chunk = os.read(key.fd, read_size)
                except (BlockingIOError, InterruptedError):
                    continue
                if not chunk:
                    _close_selector_stream(selector, stream)
                    continue
                if available == 0:
                    boundary_status = f"{channel}_limit"
                    error_code = boundary_status
                    break
                buffer.extend(chunk)

            if process.poll() is not None and not selector.get_map():
                break
        if boundary_status is None:
            process.wait()
            normal_completion = True
    except (OSError, MemoryError):
        boundary_status = "launch_error"
        error_code = "process_io_error"
    finally:
        if process_group is None:
            try:
                process.kill()
            except OSError:
                pass
            process.wait()
        elif boundary_status is not None or not normal_completion:
            _terminate_process_group(process, process_group)
        else:
            _signal_process_group(process_group, signal.SIGTERM)
            _signal_process_group(process_group, signal.SIGKILL)
        if process.stdin is not None:
            _close_selector_stream(selector, process.stdin)
        if process.stdout is not None:
            _close_selector_stream(selector, process.stdout)
        if process.stderr is not None:
            _close_selector_stream(selector, process.stderr)
        try:
            selector.close()
        except OSError:
            pass

    exit_code = process.returncode
    if boundary_status is None:
        if exit_code == 0:
            boundary_status = "completed"
        else:
            boundary_status = "nonzero_exit"
            error_code = "nonzero_exit"
    return BoundedProcessResult(
        command,
        boundary_status,
        exit_code,
        bytes(stdout),
        bytes(stderr),
        boundary_status == "timeout",
        boundary_status == "stdout_limit",
        boundary_status == "stderr_limit",
        error_code,
    )


def _execution_identity(corpus_sha256: str, target_id: str) -> str:
    payload = _canonical_json_bytes(
        {
            "corpus_sha256": corpus_sha256,
            "execution_contract_version": RUN_MANIFEST_SCHEMA_VERSION,
            "target_id": target_id,
        }
    )
    return "rt_" + hashlib.sha256(payload).hexdigest()


def _case_run_id(execution_id: str, case_id: str) -> str:
    payload = _canonical_json_bytes(
        {"case_id": case_id, "execution_id": execution_id}
    )
    return "rtc_" + hashlib.sha256(payload).hexdigest()


def _artifact_path(root: Path, *parts: str) -> Path:
    if any(
        not isinstance(part, str)
        or not part
        or Path(part).is_absolute()
        or part in (".", "..")
        or "/" in part
        or "\\" in part
        for part in parts
    ):
        raise RedTeamRunError("artifact_persistence_failed")
    candidate = root.joinpath(*parts)
    try:
        candidate.relative_to(root)
    except ValueError:
        raise RedTeamRunError("artifact_persistence_failed") from None
    return candidate


def _relative_reference(path: Path, root: Path) -> str:
    try:
        relative = path.relative_to(root)
    except ValueError:
        raise RedTeamRunError("artifact_persistence_failed") from None
    reference = relative.as_posix()
    if (
        not reference
        or len(reference) > _MAX_ARTIFACT_REF_CHARS
        or relative.is_absolute()
        or any(part in ("", ".", "..") for part in relative.parts)
    ):
        raise RedTeamRunError("artifact_persistence_failed")
    return reference


def _mkdir_new(path: Path) -> None:
    try:
        path.mkdir(mode=0o755)
    except OSError:
        raise RedTeamRunError("artifact_persistence_failed") from None


def _write_new(path: Path, data: bytes) -> None:
    try:
        atomic_write_bytes(path, data, overwrite=False)
    except OSError:
        raise RedTeamRunError("artifact_persistence_failed") from None


def _corpus_reference_bytes(accepted: AcceptedCorpus) -> bytes:
    return _canonical_json_bytes(
        {
            "case_count": len(accepted.corpus.cases),
            "corpus_schema_version": CORPUS_SCHEMA_VERSION,
            "corpus_sha256": accepted.corpus.corpus_sha256,
            "persisted_sha256": accepted.persisted_sha256,
            "schema_version": CORPUS_REFERENCE_SCHEMA_VERSION,
        }
    )


def _case_execution(
    *,
    root: Path,
    corpus_reference: bytes,
    case: CorpusCase,
    target_id: str,
    execution_id: str,
    argv: tuple[str, ...],
) -> dict[str, object]:
    target_input = target_input_from_case(case)
    target_input_bytes = canonical_contract_bytes(target_input)
    case_run_id = _case_run_id(execution_id, target_input.case_id)
    run_dir = _artifact_path(root, "runs", case_run_id)
    _mkdir_new(run_dir)
    llmfuzz_dir = _artifact_path(run_dir, "llmfuzz")
    input_dir = _artifact_path(run_dir, "input")
    exec_dir = _artifact_path(run_dir, "exec")
    for directory in (llmfuzz_dir, input_dir, exec_dir):
        _mkdir_new(directory)

    corpus_reference_path = _artifact_path(
        llmfuzz_dir, "redteam-corpus-reference.json"
    )
    target_input_path = _artifact_path(input_dir, "redteam-target-input.json")
    stdout_path = _artifact_path(exec_dir, "stdout.txt")
    stderr_path = _artifact_path(exec_dir, "stderr.txt")
    exec_path = _artifact_path(exec_dir, "exec.json")
    events_path = _artifact_path(exec_dir, "redteam-events.json")
    _write_new(corpus_reference_path, corpus_reference)
    _write_new(target_input_path, target_input_bytes)

    process_result = run_bounded_process(
        argv,
        stdin_bytes=target_input_bytes,
        cwd=run_dir,
        env=_target_environment(),
    )
    if (
        not isinstance(process_result, BoundedProcessResult)
        or process_result.status not in EXECUTION_STATUSES
        or not isinstance(process_result.stdout, bytes)
        or len(process_result.stdout) > MAX_TARGET_OUTPUT_BYTES
        or not isinstance(process_result.stderr, bytes)
        or len(process_result.stderr) > MAX_TARGET_STDERR_BYTES
    ):
        raise RedTeamRunError("execution_internal_error")
    _write_new(stdout_path, process_result.stdout)
    _write_new(stderr_path, process_result.stderr)

    status = process_result.status
    error_code = process_result.error_code
    events_reference: str | None = None
    if status == "completed":
        try:
            target_output = load_target_output_bytes(
                process_result.stdout,
                expected_input=target_input,
                expected_target_id=target_id,
            )
        except DemoTargetValidationError:
            status = "malformed_output"
            error_code = "target_output_invalid"
        else:
            _write_new(events_path, process_result.stdout)
            events_reference = _relative_reference(events_path, root)

    exec_object = {
        "argv": list(process_result.argv),
        "case_id": target_input.case_id,
        "case_run_id": case_run_id,
        "error_code": error_code,
        "events_path": (
            "exec/redteam-events.json" if events_reference is not None else None
        ),
        "exit_code": process_result.exit_code,
        "schema_version": EXECUTION_SCHEMA_VERSION,
        "status": status,
        "stderr_limit_exceeded": process_result.stderr_limit_exceeded,
        "stderr_path": "exec/stderr.txt",
        "stdout_limit_exceeded": process_result.stdout_limit_exceeded,
        "stdout_path": "exec/stdout.txt",
        "target_id": target_id,
        "timed_out": process_result.timed_out,
        "timeout_seconds": TARGET_TIMEOUT_SECONDS,
    }
    _write_new(exec_path, _canonical_json_bytes(exec_object))

    return {
        "case_id": target_input.case_id,
        "case_run_id": case_run_id,
        "corpus_reference_path": _relative_reference(corpus_reference_path, root),
        "events_path": events_reference,
        "exec_path": _relative_reference(exec_path, root),
        "run_path": _relative_reference(run_dir, root),
        "status": status,
        "stderr_path": _relative_reference(stderr_path, root),
        "stdout_path": _relative_reference(stdout_path, root),
        "target_input_path": _relative_reference(target_input_path, root),
    }


def run_accepted_corpus(
    *,
    target: str,
    output: str | os.PathLike[str],
    corpus_path: str | os.PathLike[str] | None = None,
) -> RedTeamRunResult:
    accepted = load_accepted_corpus(corpus_path)
    target_name, target_id = _validated_target_name(target)
    output_root = _validated_output_root(output)
    argv = target_command(target_name)
    execution_id = _execution_identity(accepted.corpus.corpus_sha256, target_id)
    corpus_reference = _corpus_reference_bytes(accepted)

    try:
        output_root.mkdir(mode=0o755)
    except FileExistsError:
        raise RedTeamRunValidationError("destination_exists") from None
    except OSError:
        raise RedTeamRunValidationError("destination_invalid") from None
    llmfuzz_root = _artifact_path(output_root, "llmfuzz")
    runs_root = _artifact_path(output_root, "runs")
    _mkdir_new(llmfuzz_root)
    _mkdir_new(runs_root)

    cases: list[dict[str, object]] = []
    for case in accepted.corpus.cases:
        cases.append(
            _case_execution(
                root=output_root,
                corpus_reference=corpus_reference,
                case=case,
                target_id=target_id,
                execution_id=execution_id,
                argv=argv,
            )
        )

    manifest = {
        "case_count": len(cases),
        "cases": cases,
        "corpus_sha256": accepted.corpus.corpus_sha256,
        "execution_id": execution_id,
        "persisted_sha256": accepted.persisted_sha256,
        "schema_version": RUN_MANIFEST_SCHEMA_VERSION,
        "target_id": target_id,
    }
    manifest_path = _artifact_path(llmfuzz_root, "redteam-run.json")
    _write_new(manifest_path, _canonical_json_bytes(manifest))
    completed = all(case["status"] == "completed" for case in cases)
    return RedTeamRunResult(
        output_root,
        manifest_path,
        execution_id,
        target_id,
        len(cases),
        completed,
        manifest,
    )


def canonical_run_cli_output(result: RedTeamRunResult) -> str:
    if not isinstance(result, RedTeamRunResult) or not result.completed:
        raise RedTeamRunError("execution_internal_error")
    return _canonical_json_bytes(
        {
            "case_count": result.case_count,
            "execution_id": result.execution_id,
            "manifest": "llmfuzz/redteam-run.json",
            "target_id": result.target_id,
        }
    ).decode("utf-8").rstrip("\n")
