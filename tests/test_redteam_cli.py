from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
from pathlib import Path

import pytest

import llmfuzz.cli as cli
import llmfuzz.redteam_generation as generation
from llmfuzz.redteam_corpus import (
    ASSERTION_VOCABULARY,
    ATTACK_CLASSES,
    CASE_SCHEMA_VERSION,
    MAX_CASE_COUNT,
    MIN_CASE_COUNT,
    load_corpus,
)
from llmfuzz.redteam_generation import (
    MAX_OUTPUT_TOKENS,
    GenerationError,
    GenerationRequest,
    ProviderResponse,
    ProviderUsage,
    calculate_worst_case_reservation,
)


_REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def _block_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def blocked(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("network access is forbidden in C3 tests")

    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    monkeypatch.setattr(socket.socket, "connect", blocked)


def _marker() -> str:
    return "s" + "k-test-" + "secret-must-not-appear"


def _cases(count: int) -> list[dict[str, object]]:
    return [
        {
            "schema_version": CASE_SCHEMA_VERSION,
            "case_id": f"case_{index:02d}",
            "attack_class": ATTACK_CLASSES[index % len(ATTACK_CLASSES)],
            "input": f"Synthetic adversarial input {index}",
            "expected_risk": "critical",
            "rationale": f"Concise synthetic rationale {index}",
            "assertions": [ASSERTION_VOCABULARY[index % len(ASSERTION_VOCABULARY)]],
        }
        for index in range(count)
    ]


def _response(
    count: int = 16,
    *,
    usage: ProviderUsage | None = ProviderUsage(100, 200, 300),
    output_text: str | None = None,
) -> ProviderResponse:
    return ProviderResponse(
        response_id="resp_synthetic_c3",
        model="gpt-5.6-sol",
        status="completed",
        service_tier="default",
        error_category=None,
        incomplete_reason=None,
        output_text=(
            json.dumps({"cases": _cases(count)})
            if output_text is None
            else output_text
        ),
        usage=usage,
        refusal=False,
    )


class FakeProvider:
    def __init__(self, *items: object, close_error: BaseException | None = None) -> None:
        self.items = list(items)
        self.calls: list[GenerationRequest] = []
        self.close_calls = 0
        self.close_error = close_error

    def create_response(self, request: GenerationRequest) -> ProviderResponse:
        self.calls.append(request)
        item = self.items.pop(0)
        if isinstance(item, Exception):
            raise item
        assert isinstance(item, ProviderResponse)
        return item

    def close(self) -> None:
        self.close_calls += 1
        if self.close_error is not None:
            raise self.close_error


class ForcedInterruption(BaseException):
    pass


class CleanupInterruption(BaseException):
    pass


class InterruptingProvider(FakeProvider):
    def __init__(
        self,
        interruption: BaseException,
        *,
        close_error: BaseException | None = None,
    ) -> None:
        super().__init__(close_error=close_error)
        self.interruption = interruption

    def create_response(self, request: GenerationRequest) -> ProviderResponse:
        self.calls.append(request)
        raise self.interruption


def _install_provider(
    monkeypatch: pytest.MonkeyPatch,
    provider: FakeProvider,
) -> list[None]:
    factory_calls: list[None] = []

    def factory() -> FakeProvider:
        factory_calls.append(None)
        return provider

    monkeypatch.setattr(cli, "_create_redteam_provider", factory)
    return factory_calls


def _command(path: Path, *extra: str) -> list[str]:
    return ["redteam", "generate", "--output", str(path), *extra]


def test_help_and_existing_commands_never_initialize_provider(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls: list[None] = []

    def forbidden() -> object:
        calls.append(None)
        raise AssertionError("provider initialization forbidden")

    monkeypatch.setattr(cli, "_create_redteam_provider", forbidden)
    for argv in (
        ["--help"],
        ["redteam", "--help"],
        ["redteam", "generate", "--help"],
        ["run", "--help"],
    ):
        with pytest.raises(SystemExit) as exc_info:
            cli.main(argv)
        assert exc_info.value.code == 0

    with pytest.raises(SystemExit) as exc_info:
        cli.main(["replay"])
    assert exc_info.value.code == 2
    for argv in (
        ["redteam", "generate"],
        ["redteam", "generate", "--output", "corpus.json", "--cases", "bad"],
    ):
        with pytest.raises(SystemExit) as exc_info:
            cli.main(argv)
        assert exc_info.value.code == 2
    assert calls == []
    help_output = capsys.readouterr().out
    for command in (
        "validate",
        "run",
        "run-one",
        "campaign",
        "eval-run",
        "triage-campaign",
        "replay",
        "redteam",
    ):
        assert command in help_output


def test_cli_creates_no_persistent_budget_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    home = tmp_path / "home"
    state = tmp_path / "state"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_STATE_HOME", str(state))
    for argv in (["--help"], ["redteam", "--help"], ["redteam", "generate", "--help"]):
        with pytest.raises(SystemExit) as exc_info:
            cli.main(argv)
        assert exc_info.value.code == 0

    destination = tmp_path / "corpus.json"
    provider = FakeProvider(_response())
    _install_provider(monkeypatch, provider)
    assert cli.main(_command(destination, "--max-output-tokens", "1024")) == 0
    capsys.readouterr()

    failed_destination = tmp_path / "failed.json"
    failed_provider = FakeProvider(GenerationError("provider_bad_request"))
    _install_provider(monkeypatch, failed_provider)
    with pytest.raises(SystemExit) as exc_info:
        cli.main(_command(failed_destination, "--max-output-tokens", "1024"))
    assert exc_info.value.code == 1
    capsys.readouterr()

    assert destination.exists()
    assert not failed_destination.exists()
    assert not home.exists()
    assert not state.exists()


@pytest.mark.parametrize(
    "argv",
    (
        ("--help",),
        ("redteam", "generate", "--help"),
        ("run", "--help"),
    ),
)
def test_module_entry_help_does_not_import_openai(
    tmp_path: Path,
    argv: tuple[str, ...],
) -> None:
    shadow = tmp_path / "shadow"
    shadow.mkdir()
    (shadow / "openai.py").write_text(
        "raise AssertionError('OpenAI SDK import forbidden')\n",
        encoding="utf-8",
    )
    env = {
        "OPENAI_API_KEY": "synthetic-key",
        "PATH": os.environ.get("PATH", ""),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPATH": os.pathsep.join((str(shadow), str(_REPO_ROOT))),
    }
    proc = subprocess.run(
        [sys.executable, "-m", "llmfuzz", *argv],
        cwd=_REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    assert "OpenAI SDK import forbidden" not in proc.stderr


def test_installed_entry_help_does_not_import_openai(tmp_path: Path) -> None:
    executable = shutil.which("llmfuzz")
    if executable is None:
        pytest.skip("installed llmfuzz console entry point is unavailable")
    shadow = tmp_path / "shadow"
    shadow.mkdir()
    (shadow / "openai.py").write_text(
        "raise AssertionError('OpenAI SDK import forbidden')\n",
        encoding="utf-8",
    )
    env = {
        "OPENAI_API_KEY": "synthetic-key",
        "PATH": os.environ.get("PATH", ""),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPATH": os.pathsep.join((str(shadow), str(_REPO_ROOT))),
    }
    proc = subprocess.run(
        [executable, "--help"],
        cwd=_REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    assert "OpenAI SDK import forbidden" not in proc.stderr


def test_success_uses_c2_persistence_and_prints_safe_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    destination = tmp_path / "corpus.json"
    provider = FakeProvider(_response())
    factory_calls = _install_provider(monkeypatch, provider)

    assert cli.main(_command(destination)) == 0

    captured = capsys.readouterr()
    output = json.loads(captured.out)
    persisted = load_corpus(destination)
    request = provider.calls[0]
    _, reservation = calculate_worst_case_reservation(
        prompt=generation.build_generation_prompt(16),
        text_format=request.text_format,
        max_output_tokens=MAX_OUTPUT_TOKENS,
    )
    assert captured.err == ""
    assert output == {
        "actual_estimated_cost_usd": "0.0065",
        "attempts_consumed": 1,
        "corpus_path": str(destination),
        "corpus_sha256": persisted.corpus_sha256,
        "generated_case_count": 16,
        "input_tokens": 100,
        "output_tokens": 200,
        "reserved_maximum_cost_usd": str(reservation),
        "total_tokens": 300,
    }
    assert persisted.generation_metadata.token_usage is not None
    assert len(persisted.cases) == 16
    assert request.max_output_tokens == MAX_OUTPUT_TOKENS
    schema = request.text_format["schema"]
    assert isinstance(schema, dict)
    properties = schema["properties"]
    assert isinstance(properties, dict)
    cases_schema = properties["cases"]
    assert isinstance(cases_schema, dict)
    assert cases_schema["minItems"] == 16
    assert cases_schema["maxItems"] == 16
    assert factory_calls == [None]
    assert len(provider.calls) == 1
    assert provider.close_calls == 1


def test_success_without_usage_prints_nulls_without_inventing_values(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    destination = tmp_path / "corpus.json"
    provider = FakeProvider(_response(usage=None))
    _install_provider(monkeypatch, provider)

    assert cli.main(_command(destination, "--cases", "16", "--max-output-tokens", "1024")) == 0

    output = json.loads(capsys.readouterr().out)
    persisted = load_corpus(destination)
    assert output["input_tokens"] is None
    assert output["output_tokens"] is None
    assert output["total_tokens"] is None
    assert output["actual_estimated_cost_usd"] is None
    assert persisted.generation_metadata.token_usage is None
    assert provider.close_calls == 1


@pytest.mark.parametrize(
    "extra",
    (
        ("--cases", str(MIN_CASE_COUNT - 1)),
        ("--cases", str(MAX_CASE_COUNT + 1)),
        ("--max-output-tokens", "0"),
        ("--max-output-tokens", str(MAX_OUTPUT_TOKENS + 1)),
    ),
)
def test_local_numeric_errors_precede_provider_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    extra: tuple[str, str],
) -> None:
    destination = tmp_path / "corpus.json"
    provider = FakeProvider(_response())
    factory_calls = _install_provider(monkeypatch, provider)

    with pytest.raises(SystemExit) as exc_info:
        cli.main(_command(destination, *extra))

    captured = capsys.readouterr()
    assert exc_info.value.code == 2
    assert captured.out == ""
    assert captured.err == (
        "redteam generate: Red Team generation configuration is invalid.\n"
    )
    assert factory_calls == []
    assert provider.calls == []
    assert not destination.exists()


@pytest.mark.parametrize("output", ("", "bad\0path"))
def test_invalid_destination_shape_precedes_provider_creation(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    output: str,
) -> None:
    provider = FakeProvider(_response())
    factory_calls = _install_provider(monkeypatch, provider)

    with pytest.raises(SystemExit) as exc_info:
        cli.main(["redteam", "generate", "--output", output])

    captured = capsys.readouterr()
    assert exc_info.value.code == 2
    assert captured.err == "redteam generate: Generation destination is invalid.\n"
    assert factory_calls == []
    assert provider.calls == []


def test_existing_destination_is_not_overwritten_or_initialized(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    destination = tmp_path / "corpus.json"
    destination.write_bytes(b"existing\n")
    provider = FakeProvider(_response())
    factory_calls = _install_provider(monkeypatch, provider)

    with pytest.raises(SystemExit) as exc_info:
        cli.main(_command(destination))

    captured = capsys.readouterr()
    assert exc_info.value.code == 2
    assert captured.err == "redteam generate: Generation destination already exists.\n"
    assert destination.read_bytes() == b"existing\n"
    assert factory_calls == []
    assert provider.calls == []


def test_non_directory_ancestor_precedes_provider_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    parent = tmp_path / "parent"
    parent.write_text("not a directory", encoding="utf-8")
    destination = parent / "corpus.json"
    provider = FakeProvider(_response())
    factory_calls = _install_provider(monkeypatch, provider)

    with pytest.raises(SystemExit) as exc_info:
        cli.main(_command(destination))

    assert exc_info.value.code == 2
    assert capsys.readouterr().err == "redteam generate: Generation destination is invalid.\n"
    assert factory_calls == []
    assert provider.calls == []


def test_unwritable_ancestor_precedes_provider_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    destination = tmp_path / "nested" / "corpus.json"
    provider = FakeProvider(_response())
    factory_calls = _install_provider(monkeypatch, provider)
    monkeypatch.setattr(os, "access", lambda *_args, **_kwargs: False)

    with pytest.raises(SystemExit) as exc_info:
        cli.main(_command(destination))

    assert exc_info.value.code == 2
    assert capsys.readouterr().err == "redteam generate: Generation destination is invalid.\n"
    assert factory_calls == []
    assert provider.calls == []
    assert not destination.exists()


@pytest.mark.parametrize(
    ("code", "message"),
    (
        ("missing_api_key", "OpenAI API key is required for generation."),
        ("openai_sdk_unavailable", "OpenAI generation support is not installed."),
        ("openai_environment_not_isolated", "OpenAI generation environment is not isolated."),
    ),
)
def test_sanitized_provider_initialization_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    code: str,
    message: str,
) -> None:
    destination = tmp_path / "corpus.json"

    def fail() -> object:
        raise GenerationError(code)

    monkeypatch.setattr(cli, "_create_redteam_provider", fail)
    with pytest.raises(SystemExit) as exc_info:
        cli.main(_command(destination))

    captured = capsys.readouterr()
    assert exc_info.value.code == 1
    assert exc_info.value.__cause__ is None
    assert exc_info.value.__context__ is None
    assert captured.out == ""
    assert captured.err == f"redteam generate: {message}\n"
    assert not destination.exists()


def test_unexpected_provider_initialization_error_is_sanitized(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    destination = tmp_path / "corpus.json"
    marker = _marker()

    def fail() -> object:
        raise RuntimeError(marker)

    monkeypatch.setattr(cli, "_create_redteam_provider", fail)
    with pytest.raises(SystemExit) as exc_info:
        cli.main(_command(destination))

    captured = capsys.readouterr()
    assert exc_info.value.code == 1
    assert exc_info.value.__cause__ is None
    assert exc_info.value.__context__ is None
    assert captured.err == "redteam generate: OpenAI provider initialization failed.\n"
    assert marker not in captured.out + captured.err
    assert not destination.exists()


def test_hostile_generation_error_string_is_not_exposed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    destination = tmp_path / "corpus.json"
    marker = _marker()

    class HostileGenerationError(GenerationError):
        def __str__(self) -> str:
            return marker

    def fail() -> object:
        raise HostileGenerationError("missing_api_key")

    monkeypatch.setattr(cli, "_create_redteam_provider", fail)
    with pytest.raises(SystemExit) as exc_info:
        cli.main(_command(destination))

    captured = capsys.readouterr()
    assert exc_info.value.code == 1
    assert captured.err == "redteam generate: OpenAI API key is required for generation.\n"
    assert marker not in captured.out + captured.err
    assert not destination.exists()


@pytest.mark.parametrize(
    "code",
    (
        "attempt_limit_exceeded",
        "budget_limit_exceeded",
        "response_invalid_payload",
        "persistence_failed",
    ),
)
def test_generation_errors_are_authoritative_and_close_provider(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    code: str,
) -> None:
    destination = tmp_path / "corpus.json"
    provider = FakeProvider(_response())
    _install_provider(monkeypatch, provider)

    def fail(**_kwargs: object) -> object:
        raise GenerationError(code)

    monkeypatch.setattr(cli, "generate_and_persist_corpus", fail)
    with pytest.raises(SystemExit) as exc_info:
        cli.main(_command(destination))

    captured = capsys.readouterr()
    assert exc_info.value.code == 1
    assert captured.err == f"redteam generate: {GenerationError(code)}\n"
    assert provider.close_calls == 1
    assert not destination.exists()


def test_retry_exhaustion_uses_c2_and_closes_provider(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    destination = tmp_path / "corpus.json"
    provider = FakeProvider(
        GenerationError("provider_connection", retryable=True),
        GenerationError("provider_connection", retryable=True),
    )
    _install_provider(monkeypatch, provider)

    with pytest.raises(SystemExit) as exc_info:
        cli.main(_command(destination, "--max-output-tokens", "1024"))

    captured = capsys.readouterr()
    assert exc_info.value.code == 1
    assert captured.err == "redteam generate: OpenAI provider connection failed.\n"
    assert len(provider.calls) == 2
    assert provider.close_calls == 1
    assert not destination.exists()


def test_invalid_provider_output_uses_c2_and_leaves_no_corpus(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    destination = tmp_path / "corpus.json"
    provider = FakeProvider(
        _response(output_text="{"),
        _response(output_text="{"),
    )
    _install_provider(monkeypatch, provider)

    with pytest.raises(SystemExit) as exc_info:
        cli.main(_command(destination, "--max-output-tokens", "1024"))

    assert exc_info.value.code == 1
    assert capsys.readouterr().err == (
        "redteam generate: Generated response text was not valid JSON.\n"
    )
    assert len(provider.calls) == 2
    assert provider.close_calls == 1
    assert not destination.exists()


def test_c2_persistence_failure_is_sanitized_and_not_retried(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    destination = tmp_path / "corpus.json"
    provider = FakeProvider(_response())
    _install_provider(monkeypatch, provider)

    def fail_persistence(*_args: object, **_kwargs: object) -> object:
        raise OSError(_marker())

    monkeypatch.setattr(generation, "persist_corpus", fail_persistence)
    with pytest.raises(SystemExit) as exc_info:
        cli.main(_command(destination, "--max-output-tokens", "1024"))

    captured = capsys.readouterr()
    assert exc_info.value.code == 1
    assert captured.err == "redteam generate: Generated corpus persistence failed.\n"
    assert len(provider.calls) == 1
    assert provider.close_calls == 1
    assert not destination.exists()
    assert _marker() not in captured.out + captured.err


def test_close_failure_after_success_is_nonzero_and_preserves_verified_corpus(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    destination = tmp_path / "corpus.json"
    marker = _marker()
    provider = FakeProvider(_response(), close_error=RuntimeError(marker))
    _install_provider(monkeypatch, provider)

    with pytest.raises(SystemExit) as exc_info:
        cli.main(_command(destination, "--max-output-tokens", "1024"))

    captured = capsys.readouterr()
    assert exc_info.value.code == 1
    assert exc_info.value.__cause__ is None
    assert exc_info.value.__context__ is None
    assert captured.out == ""
    assert captured.err == "redteam generate: OpenAI provider cleanup failed.\n"
    assert marker not in captured.out + captured.err
    assert load_corpus(destination).corpus_sha256
    assert provider.close_calls == 1


def test_primary_generation_failure_wins_when_close_also_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    destination = tmp_path / "corpus.json"
    marker = _marker()
    provider = FakeProvider(_response(), close_error=RuntimeError(marker))
    _install_provider(monkeypatch, provider)

    def fail(**_kwargs: object) -> object:
        raise GenerationError("attempt_limit_exceeded")

    monkeypatch.setattr(cli, "generate_and_persist_corpus", fail)
    with pytest.raises(SystemExit) as exc_info:
        cli.main(_command(destination))

    captured = capsys.readouterr()
    assert exc_info.value.code == 1
    assert exc_info.value.__cause__ is None
    assert exc_info.value.__context__ is None
    assert captured.out == ""
    assert captured.err == (
        "redteam generate: Red Team generation attempt limit would be exceeded.\n"
    )
    assert "cleanup" not in captured.err.lower()
    assert marker not in captured.out + captured.err
    assert provider.close_calls == 1
    assert not destination.exists()


def test_unexpected_generation_error_is_sanitized_and_closes_provider(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    destination = tmp_path / "corpus.json"
    marker = _marker()
    provider = FakeProvider(_response())
    _install_provider(monkeypatch, provider)

    def fail(**_kwargs: object) -> object:
        raise RuntimeError(marker)

    monkeypatch.setattr(cli, "generate_and_persist_corpus", fail)
    with pytest.raises(SystemExit) as exc_info:
        cli.main(_command(destination))

    captured = capsys.readouterr()
    assert exc_info.value.code == 1
    assert exc_info.value.__cause__ is None
    assert exc_info.value.__context__ is None
    assert captured.err == "redteam generate: Red Team corpus generation failed.\n"
    assert marker not in captured.out + captured.err
    assert provider.close_calls == 1
    assert not destination.exists()


@pytest.mark.parametrize(
    "primary_factory",
    (
        pytest.param(lambda: KeyboardInterrupt(), id="keyboard_interrupt"),
        pytest.param(lambda: SystemExit(73), id="system_exit"),
        pytest.param(lambda: ForcedInterruption(), id="custom_base_exception"),
    ),
)
@pytest.mark.parametrize(
    "cleanup_factory",
    (
        pytest.param(lambda _marker: None, id="close_success"),
        pytest.param(lambda marker: RuntimeError(marker), id="runtime_error"),
        pytest.param(lambda _marker: KeyboardInterrupt(), id="keyboard_interrupt"),
        pytest.param(lambda _marker: SystemExit(74), id="system_exit"),
        pytest.param(
            lambda marker: CleanupInterruption(marker),
            id="custom_base_exception",
        ),
    ),
)
def test_active_base_exception_wins_over_every_cleanup_outcome(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    primary_factory: object,
    cleanup_factory: object,
) -> None:
    marker = _marker()
    assert callable(primary_factory)
    assert callable(cleanup_factory)
    interruption = primary_factory()
    cleanup_error = cleanup_factory(marker)
    provider = InterruptingProvider(
        interruption,
        close_error=cleanup_error,
    )
    _install_provider(monkeypatch, provider)
    destination = tmp_path / "corpus.json"

    with pytest.raises(type(interruption)) as exc_info:
        cli.main(
            _command(destination, "--max-output-tokens", "1024")
        )

    captured = capsys.readouterr()
    assert exc_info.value is interruption
    assert exc_info.value.__cause__ is None
    assert exc_info.value.__context__ is None
    assert captured.out == ""
    assert captured.err == ""
    assert marker not in captured.out + captured.err
    assert provider.close_calls == 1
    assert len(provider.calls) == 1
    assert not destination.exists()


def test_base_exception_during_success_output_still_closes_and_preserves_corpus(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    interruption = ForcedInterruption()
    provider = FakeProvider(
        _response(),
        close_error=CleanupInterruption(_marker()),
    )
    _install_provider(monkeypatch, provider)
    destination = tmp_path / "corpus.json"

    def interrupt_output(_result: object) -> str:
        raise interruption

    monkeypatch.setattr(cli, "_redteam_success_output", interrupt_output)
    with pytest.raises(ForcedInterruption) as exc_info:
        cli.main(
            _command(destination, "--max-output-tokens", "1024")
        )

    captured = capsys.readouterr()
    assert exc_info.value is interruption
    assert exc_info.value.__cause__ is None
    assert exc_info.value.__context__ is None
    assert captured.out == ""
    assert captured.err == ""
    assert provider.close_calls == 1
    assert load_corpus(destination).corpus_sha256
