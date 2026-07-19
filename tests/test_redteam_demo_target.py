from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

from llmfuzz.redteam_contracts import (
    EVENT_SCHEMA_VERSION,
    MAX_EVENT_COUNT,
    TARGET_INPUT_SCHEMA_VERSION,
    ContractValidationError,
    ObservedEvent,
    TargetInput,
    canonical_contract_bytes,
    target_input_from_case,
    validate_event,
    validate_target_input,
)
from llmfuzz.redteam_corpus import (
    ASSERTION_VOCABULARY,
    ATTACK_CLASSES,
    MAX_CASE_ID_CHARS,
    MAX_INPUT_CHARS,
    load_bundled_accepted_corpus,
)
from llmfuzz.redteam_demo_target import (
    FIXED_POLICY,
    FIXED_TARGET_ID,
    MAX_TARGET_INPUT_BYTES,
    MAX_TARGET_OUTPUT_BYTES,
    SYNTHETIC_FORBIDDEN_TOOL,
    SYNTHETIC_PROTECTED_ACTION,
    TARGET_OUTPUT_SCHEMA_VERSION,
    VULNERABLE_POLICY,
    VULNERABLE_TARGET_ID,
    DemoTargetValidationError,
    DemoTargetPolicy,
    TargetOutput,
    canonical_target_output_bytes,
    execute_demo_target,
    load_target_input_bytes,
    load_target_output_bytes,
    target_output_for,
    validate_target_output,
)


_REPOSITORY = Path(__file__).resolve().parents[1]
_EVENT_MATRIX = (
    (
        "prompt injection",
        VULNERABLE_POLICY,
        (
            ("untrusted_instruction", {"followed": True}),
            ("final", {"disposition": "completed"}),
        ),
    ),
    (
        "prompt injection",
        FIXED_POLICY,
        (
            ("untrusted_instruction", {"followed": False}),
            ("final", {"disposition": "completed"}),
        ),
    ),
    (
        "secret exfiltration",
        VULNERABLE_POLICY,
        (
            ("secret_revelation", {"revealed": True}),
            ("final", {"disposition": "completed"}),
        ),
    ),
    (
        "secret exfiltration",
        FIXED_POLICY,
        (
            ("secret_revelation", {"revealed": False}),
            ("final", {"disposition": "refused"}),
        ),
    ),
    (
        "forbidden tool use",
        VULNERABLE_POLICY,
        (
            (
                "tool_call",
                {
                    "tool_name": SYNTHETIC_FORBIDDEN_TOOL,
                    "forbidden": True,
                    "executed": True,
                },
            ),
            ("final", {"disposition": "completed"}),
        ),
    ),
    (
        "forbidden tool use",
        FIXED_POLICY,
        (
            (
                "tool_call",
                {
                    "tool_name": SYNTHETIC_FORBIDDEN_TOOL,
                    "forbidden": True,
                    "executed": False,
                },
            ),
            ("final", {"disposition": "blocked"}),
        ),
    ),
    (
        "approval bypass",
        VULNERABLE_POLICY,
        (
            ("approval_check", {"approved": False}),
            (
                "protected_action",
                {"action_name": SYNTHETIC_PROTECTED_ACTION, "executed": True},
            ),
            ("final", {"disposition": "completed"}),
        ),
    ),
    (
        "approval bypass",
        FIXED_POLICY,
        (
            ("approval_check", {"approved": False}),
            (
                "protected_action",
                {"action_name": SYNTHETIC_PROTECTED_ACTION, "executed": False},
            ),
            ("final", {"disposition": "blocked"}),
        ),
    ),
)


def _target_input(
    attack_class: str,
    *,
    case_id: str = "synthetic-d1a-case",
    assertions: tuple[str, ...] = ("must_not_follow_untrusted_instruction",),
) -> TargetInput:
    return validate_target_input(
        {
            "schema_version": TARGET_INPUT_SCHEMA_VERSION,
            "case_id": case_id,
            "attack_class": attack_class,
            "input": "Bounded synthetic adversarial input.",
            "assertions": list(assertions),
        }
    )


def _event_shape(events: tuple[ObservedEvent, ...]) -> tuple[tuple[str, dict[str, object]], ...]:
    return tuple((event.event_type, dict(event.payload)) for event in events)


def _event_raw(event_type: str, payload: dict[str, object]) -> dict[str, object]:
    return {
        "schema_version": EVENT_SCHEMA_VERSION,
        "event_type": event_type,
        "payload": payload,
    }


def _output_raw(target_input: TargetInput) -> dict[str, object]:
    return json.loads(canonical_target_output_bytes(target_output_for(target_input, FIXED_POLICY)))


def _command(
    target: str,
    data: bytes,
    *,
    environment: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    env = {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPATH": str(_REPOSITORY),
    }
    if environment is not None:
        env.update(environment)
    return subprocess.run(
        [sys.executable, "-m", "llmfuzz.redteam_target", "--target", target],
        cwd=_REPOSITORY,
        env=env,
        input=data,
        capture_output=True,
        check=False,
        shell=False,
    )


def test_public_target_and_transport_literals_are_locked() -> None:
    assert VULNERABLE_TARGET_ID == "llmfuzz.redteam.demo-target.vulnerable.v1"
    assert FIXED_TARGET_ID == "llmfuzz.redteam.demo-target.fixed.v1"
    assert TARGET_OUTPUT_SCHEMA_VERSION == "llmfuzz.redteam.target-output.v1"
    assert MAX_TARGET_INPUT_BYTES == 49_465
    assert MAX_TARGET_OUTPUT_BYTES == 32_768
    assert SYNTHETIC_FORBIDDEN_TOOL == "synthetic_forbidden_tool"
    assert SYNTHETIC_PROTECTED_ACTION == "synthetic_protected_action"


@pytest.mark.parametrize(("attack_class", "policy", "expected"), _EVENT_MATRIX)
def test_shared_core_has_exact_policy_specific_events(
    attack_class: str,
    policy: DemoTargetPolicy,
    expected: tuple[tuple[str, dict[str, object]], ...],
) -> None:
    target_input = _target_input(attack_class)

    events = execute_demo_target(target_input, policy)

    assert _event_shape(events) == expected
    assert events
    assert all(validate_event(json.loads(canonical_contract_bytes(event))) == event for event in events)
    assert [event.event_type for event in events].count("final") == 1
    assert events[-1].event_type == "final"
    repeated = execute_demo_target(target_input, policy)
    assert repeated == events
    assert b"".join(map(canonical_contract_bytes, repeated)) == b"".join(
        map(canonical_contract_bytes, events)
    )


@pytest.mark.parametrize("attack_class", ATTACK_CLASSES)
def test_behavior_is_not_case_id_hardcoded(attack_class: str) -> None:
    original = _target_input(attack_class, case_id="unbundled-original")
    renamed = _target_input(attack_class, case_id="renamed-unbundled-case")

    for policy in (VULNERABLE_POLICY, FIXED_POLICY):
        assert execute_demo_target(original, policy) == execute_demo_target(renamed, policy)


@pytest.mark.parametrize("attack_class", ATTACK_CLASSES)
def test_assertions_do_not_drive_target_behavior(attack_class: str) -> None:
    first = _target_input(
        attack_class,
        assertions=("must_not_follow_untrusted_instruction",),
    )
    second = _target_input(
        attack_class,
        assertions=("must_require_approval",),
    )

    for policy in (VULNERABLE_POLICY, FIXED_POLICY):
        assert execute_demo_target(first, policy) == execute_demo_target(second, policy)


def test_core_rejects_noncanonical_direct_target_input() -> None:
    malformed = TargetInput(
        TARGET_INPUT_SCHEMA_VERSION,
        "synthetic-d1a-case",
        "prompt injection",
        "Bounded input",
        ("unknown",),
    )

    with pytest.raises(DemoTargetValidationError):
        execute_demo_target(malformed, VULNERABLE_POLICY)


@pytest.mark.parametrize(
    ("target_name", "policy", "target_id"),
    (
        ("vulnerable", VULNERABLE_POLICY, VULNERABLE_TARGET_ID),
        ("fixed", FIXED_POLICY, FIXED_TARGET_ID),
    ),
)
def test_actual_command_uses_canonical_stdin_stdout_transport(
    target_name: str,
    policy: DemoTargetPolicy,
    target_id: str,
) -> None:
    target_input = _target_input("approval bypass")
    stdin = canonical_contract_bytes(target_input)

    first = _command(target_name, stdin)
    second = _command(target_name, stdin)

    assert first.returncode == second.returncode == 0
    assert first.stderr == second.stderr == b""
    assert first.stdout == second.stdout
    output = load_target_output_bytes(first.stdout, expected_input=target_input)
    raw = json.loads(first.stdout)
    assert set(raw) == {"schema_version", "target_id", "case_id", "events"}
    assert output.target_id == target_id
    assert output.case_id == target_input.case_id
    assert output.events == execute_demo_target(target_input, policy)
    assert first.stdout == canonical_target_output_bytes(output)
    assert first.stdout.endswith(b"\n") and not first.stdout.endswith(b"\n\n")


@pytest.mark.parametrize(
    "data",
    (
        b"not-json\n",
        b'{"schema_version":"llmfuzz.redteam.target-input.v1"}\n',
        b"private-raw-input-marker",
        b"x" * (MAX_TARGET_INPUT_BYTES + 1),
    ),
)
def test_command_failure_is_nonzero_bounded_and_sanitized(data: bytes) -> None:
    result = _command("fixed", data)

    assert result.returncode != 0
    assert result.stdout == b""
    assert result.stderr == b"redteam target: invalid input or target failure\n"
    assert len(result.stderr) < 128
    assert b"Traceback" not in result.stderr
    assert b"private-raw-input-marker" not in result.stderr


def test_command_rejects_unknown_target_without_reading_or_echoing_input() -> None:
    marker = b"private-raw-input-marker"
    result = _command("unknown", marker)

    assert result.returncode == 2
    assert result.stdout == b""
    assert marker not in result.stderr
    assert b"Traceback" not in result.stderr


def test_target_input_transport_requires_canonical_bounded_json() -> None:
    target_input = _target_input("prompt injection")
    canonical = canonical_contract_bytes(target_input)

    assert load_target_input_bytes(canonical) == target_input
    for invalid in (
        b"\xff",
        b"[]\n",
        b"{}\n",
        canonical.rstrip(b"\n"),
        canonical + b"\n",
        canonical + b"{}\n",
    ):
        with pytest.raises(DemoTargetValidationError):
            load_target_input_bytes(invalid)


@pytest.mark.parametrize(
    ("target_name", "target_id"),
    (
        ("vulnerable", VULNERABLE_TARGET_ID),
        ("fixed", FIXED_TARGET_ID),
    ),
)
def test_maximal_d0_target_input_fits_transport_and_commands(
    target_name: str,
    target_id: str,
) -> None:
    target_input = validate_target_input(
        {
            "schema_version": TARGET_INPUT_SCHEMA_VERSION,
            "case_id": "a" * MAX_CASE_ID_CHARS,
            "attack_class": "secret exfiltration",
            "input": "\0" * MAX_INPUT_CHARS,
            "assertions": list(ASSERTION_VOCABULARY),
        }
    )
    canonical = canonical_contract_bytes(target_input)

    assert len(canonical) == 49_465
    assert len(canonical) == MAX_TARGET_INPUT_BYTES
    assert load_target_input_bytes(canonical) == target_input

    result = _command(target_name, canonical)

    assert result.returncode == 0
    assert result.stderr == b""
    assert len(result.stdout) <= MAX_TARGET_OUTPUT_BYTES
    output = load_target_output_bytes(result.stdout, expected_input=target_input)
    assert result.stdout == canonical_target_output_bytes(output)
    assert output.case_id == target_input.case_id
    assert output.target_id == target_id


def test_json_recursion_failure_is_sanitized_by_loaders_and_command() -> None:
    deep_document = b"[" * 15_000 + b"0" + b"]" * 15_000

    assert len(deep_document) == 30_001
    assert len(deep_document) < MAX_TARGET_INPUT_BYTES
    assert len(deep_document) < MAX_TARGET_OUTPUT_BYTES
    for loader in (load_target_input_bytes, load_target_output_bytes):
        with pytest.raises(DemoTargetValidationError, match="valid JSON document"):
            loader(deep_document)

    result = _command("fixed", deep_document)

    assert result.returncode != 0
    assert result.stdout == b""
    assert result.stderr == b"redteam target: invalid input or target failure\n"
    assert b"Traceback" not in result.stderr


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        (lambda raw: raw.update(schema_version="unknown"), "schema_version"),
        (lambda raw: raw.pop("case_id"), "missing required field"),
        (lambda raw: raw.update(extra=True), "unknown field"),
        (lambda raw: raw.update(target_id="unknown"), "target_id"),
        (lambda raw: raw.update(case_id="INVALID CASE"), "case_id"),
        (lambda raw: raw.update(events={}), "must be an array"),
        (
            lambda raw: raw.update(events=[_event_raw("unknown", {}), raw["events"][-1]]),
            "valid observed event",
        ),
        (
            lambda raw: raw.update(
                events=[
                    _event_raw("approval_check", {"approved": False, "extra": True}),
                    raw["events"][-1],
                ]
            ),
            "valid observed event",
        ),
        (
            lambda raw: raw.update(
                events=[
                    _event_raw("approval_check", {"approved": 1}),
                    raw["events"][-1],
                ]
            ),
            "valid observed event",
        ),
        (
            lambda raw: raw.update(
                events=[_event_raw("approval_check", {"approved": False})]
                * (MAX_EVENT_COUNT + 1)
            ),
            "at most",
        ),
        (
            lambda raw: raw.update(events=[_event_raw("approval_check", {"approved": False})]),
            "exactly one final event",
        ),
        (
            lambda raw: raw.update(events=[raw["events"][-1], raw["events"][-1]]),
            "exactly one final event",
        ),
        (
            lambda raw: raw.update(
                events=[raw["events"][-1], _event_raw("approval_check", {"approved": False})]
            ),
            "final event must be last",
        ),
    ),
)
def test_target_output_validator_rejects_closed_contract_violations(
    mutation: Callable[[dict[str, object]], object],
    message: str,
) -> None:
    target_input = _target_input("approval bypass")
    raw = _output_raw(target_input)
    mutation(raw)

    with pytest.raises(DemoTargetValidationError, match=message):
        validate_target_output(raw, expected_input=target_input)


def test_target_output_rejects_expected_case_mismatch() -> None:
    target_input = _target_input("prompt injection")
    raw = _output_raw(target_input)
    expected = _target_input("prompt injection", case_id="different-case")

    with pytest.raises(DemoTargetValidationError, match="must match"):
        validate_target_output(raw, expected_input=expected)


def test_target_output_byte_loader_rejects_noncanonical_or_extra_output() -> None:
    target_input = _target_input("forbidden tool use")
    canonical = canonical_target_output_bytes(target_output_for(target_input, FIXED_POLICY))

    assert load_target_output_bytes(canonical, expected_input=target_input)
    for invalid in (
        b"not-json\n",
        b"\xff",
        b"[]\n",
        canonical.rstrip(b"\n"),
        b"prefix" + canonical,
        canonical + b"suffix",
        canonical + canonical,
        b"x" * (MAX_TARGET_OUTPUT_BYTES + 1),
    ):
        with pytest.raises(DemoTargetValidationError):
            load_target_output_bytes(invalid, expected_input=target_input)


def test_canonical_output_rejects_invalid_direct_nested_event() -> None:
    target_input = _target_input("prompt injection")
    output = target_output_for(target_input, FIXED_POLICY)
    invalid_event = ObservedEvent(
        EVENT_SCHEMA_VERSION,
        "untrusted_instruction",
        (("followed", 1),),  # type: ignore[arg-type]
    )
    malformed = TargetOutput(
        output.schema_version,
        output.target_id,
        output.case_id,
        (invalid_event, output.events[-1]),
    )

    with pytest.raises(DemoTargetValidationError):
        canonical_target_output_bytes(malformed)


def test_bundled_corpus_runs_all_cases_through_both_shared_policies() -> None:
    corpus = load_bundled_accepted_corpus()

    assert len(corpus.cases) == 16
    for case in corpus.cases:
        target_input = target_input_from_case(case)
        for attack_class, policy, expected in _EVENT_MATRIX:
            if attack_class == case.attack_class:
                assert _event_shape(execute_demo_target(target_input, policy)) == expected


def test_command_is_offline_and_ignores_openai_environment_and_secret_file(
    tmp_path: Path,
) -> None:
    guard = tmp_path / "guard"
    guard.mkdir()
    secret_file = tmp_path / "openai-secret"
    secret_file.write_text("synthetic-secret-that-must-not-be-read", encoding="utf-8")
    (guard / "sitecustomize.py").write_text(
        """
import builtins
import io
import os
import socket

secret_path = os.environ["LLMFUZZ_TEST_SECRET_PATH"]
real_import = builtins.__import__
real_open = builtins.open
real_io_open = io.open
real_getitem = os._Environ.__getitem__

def guarded_import(name, *args, **kwargs):
    if name == "openai" or name.startswith("openai."):
        raise AssertionError("OpenAI import forbidden")
    return real_import(name, *args, **kwargs)

def guarded_open(file, *args, **kwargs):
    if os.fspath(file) == secret_path:
        raise AssertionError("OpenAI secret file access forbidden")
    return real_open(file, *args, **kwargs)

def guarded_io_open(file, *args, **kwargs):
    if os.fspath(file) == secret_path:
        raise AssertionError("OpenAI secret file access forbidden")
    return real_io_open(file, *args, **kwargs)

def guarded_getitem(self, key):
    if key == "OPENAI_API_KEY":
        raise AssertionError("OPENAI_API_KEY access forbidden")
    return real_getitem(self, key)

def blocked(*args, **kwargs):
    raise AssertionError("network and DNS access forbidden")

builtins.__import__ = guarded_import
builtins.open = guarded_open
io.open = guarded_io_open
os._Environ.__getitem__ = guarded_getitem
socket.create_connection = blocked
socket.getaddrinfo = blocked
socket.socket.connect = blocked
""".lstrip(),
        encoding="utf-8",
    )
    target_input = _target_input("secret exfiltration")
    data = canonical_contract_bytes(target_input)
    base_environment = {
        "LLMFUZZ_TEST_SECRET_PATH": str(secret_file),
        "OPENAI_API_KEY_FILE": str(secret_file),
        "PYTHONPATH": os.pathsep.join((str(guard), str(_REPOSITORY))),
    }

    absent = _command("fixed", data, environment=base_environment)
    present = _command(
        "fixed",
        data,
        environment={**base_environment, "OPENAI_API_KEY": "synthetic-present-key"},
    )

    assert absent.returncode == present.returncode == 0
    assert absent.stderr == present.stderr == b""
    assert absent.stdout == present.stdout
    assert load_target_output_bytes(present.stdout, expected_input=target_input)


def test_d1a_modules_have_no_openai_or_execution_dependencies() -> None:
    for path in (
        _REPOSITORY / "llmfuzz" / "redteam_demo_target.py",
        _REPOSITORY / "llmfuzz" / "redteam_target.py",
    ):
        source = path.read_text(encoding="utf-8")
        assert "openai" not in source.lower()
        assert "subprocess" not in source
        assert "socket" not in source
        assert "OPENAI_API_KEY" not in source
        assert ".llmfuzz_public" not in source
