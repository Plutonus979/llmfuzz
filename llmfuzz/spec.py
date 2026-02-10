from __future__ import annotations

import json
import os
import re
import shutil
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Tuple

from .mutations import ALLOWED_OPS
from .command_allowlist import (
    ALLOWED_COMMAND_ROOTS as _ALLOWED_COMMAND_ROOTS,
    ALLOWED_COMMAND_USR_LOCAL as _ALLOWED_COMMAND_USR_LOCAL,
    ALLOWED_ABS_EXEC_ROOTS as _ALLOWED_ABS_EXEC_ROOTS,
    CONTROLLED_PATH as _CONTROLLED_PATH,
)

SCHEMA_VERSION = "llmfuzz.fuzzspec.v1"
_ALLOWED_WORK_ROOT_MODES = {"per_run", "shared"}
_ALLOWED_ENV_KEYS = {"PYTHONUNBUFFERED"}
_OUTPUT_TOKEN_RE = re.compile(r"<[^>]+>")
_HEX64_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_DEFAULT_WORK_ROOT_MODE = "per_run"
_DEFAULT_OUTPUT_TEMPLATES = {
    "input_dir": "runs/<run_id>/input",
    "out_dir": "runs/<run_id>/out",
    "eval_dir": "runs/<run_id>/eval",
    "llmfuzz_dir": "runs/<run_id>/llmfuzz",
}


class ValidationError(Exception):
    pass


@dataclass(frozen=True)
class TargetSpec:
    work_root_base: Path
    agent_id: str
    runtime_root: Optional[Path]
    engine_policy: Optional[Path]
    run_agent_script: Optional[Path]
    engine: Optional[str]
    command: Optional[Tuple[str, ...]]
    timeout_s: Optional[float]


@dataclass(frozen=True)
class SeedSpec:
    path: Path
    media_type: Optional[str]
    sha256: Optional[str]


@dataclass(frozen=True)
class MutationsSpec:
    cases: int
    rng_seed: Optional[int] = None
    max_bytes: Optional[int] = None
    max_ops_per_case: int = 1
    strategies: Optional[Tuple[str, ...]] = None


@dataclass(frozen=True)
class ExecutionSpec:
    work_root_mode: str
    env_overrides: Optional[Dict[str, str]]


@dataclass(frozen=True)
class OutputsSpec:
    input_dir: Optional[str]
    out_dir: str
    eval_dir: str
    llmfuzz_dir: Optional[str]


@dataclass(frozen=True)
class FuzzSpec:
    schema_version: str
    campaign_id: str
    description: Optional[str]
    target: TargetSpec
    seed: SeedSpec
    mutations: MutationsSpec
    execution: ExecutionSpec
    outputs: OutputsSpec


def _fail(path: str, reason: str) -> None:
    raise ValidationError(f"{path}: {reason}")


def _field_path(prefix: str, key: str) -> str:
    return f"{prefix}.{key}" if prefix else key


def _require_object(value: object, path: str) -> Dict[str, object]:
    if not isinstance(value, dict):
        _fail(path, "must be an object")
    return value


def _validate_keys(
    obj: object,
    allowed: set[str],
    required: Tuple[str, ...],
    path: str,
) -> Dict[str, object]:
    obj = _require_object(obj, path)
    for key in required:
        if key not in obj:
            _fail(_field_path(path, key), "missing required field")
    for key in sorted(obj.keys()):
        if key not in allowed:
            _fail(_field_path(path, key), "unknown field")
    return obj


def _require_string(value: object, path: str) -> str:
    if not isinstance(value, str):
        _fail(path, "must be a string")
    return value


def _parse_abs_path(value: object, path: str) -> Path:
    value = _require_string(value, path)
    candidate = Path(value)
    if not candidate.is_absolute():
        _fail(path, "must be an absolute path")
    return candidate


def _require_int_gt_zero(value: object, path: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        _fail(path, "must be an integer")
    if value <= 0:
        _fail(path, "must be greater than 0")
    return value


def _require_int_ge_zero(value: object, path: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        _fail(path, "must be an integer")
    if value < 0:
        _fail(path, "must be greater than or equal to 0")
    return value


def _require_int(value: object, path: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        _fail(path, "must be an integer")
    return value


def _require_number_gt_zero(value: object, path: str) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        _fail(path, "must be a number")
    if float(value) <= 0:
        _fail(path, "must be greater than 0")
    return float(value)


def _validate_command_argv(value: object, path: str) -> Tuple[str, ...]:
    if not isinstance(value, list):
        _fail(path, "must be an array")
    if not value:
        _fail(path, "must not be empty")
    for item in value:
        if not isinstance(item, str):
            _fail(path, "must contain strings")
    argv = tuple(value)
    _validate_command_executable(argv, path)
    return argv


def _validate_mutation_strategies(value: object, path: str) -> Tuple[str, ...]:
    if not isinstance(value, list):
        _fail(path, "must be an array")
    out: list[str] = []
    for item in value:
        if not isinstance(item, str):
            _fail(path, "must contain strings")
        if item not in ALLOWED_OPS:
            _fail(path, f"unsupported op {item}")
        out.append(item)
    return tuple(out)


def _validate_output_template(value: object, path: str) -> str:
    value = _require_string(value, path)
    if value.startswith("/"):
        _fail(path, "must not start with /")
    tokens = _OUTPUT_TOKEN_RE.findall(value)
    for token in tokens:
        if token == "<artifact_id>":
            _fail(path, "must not contain <artifact_id>")
        if token != "<run_id>":
            _fail(path, f"unsupported token {token}")
    return value


def _is_relative_to(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def _validate_command_executable(argv: Tuple[str, ...], path: str) -> None:
    argv0 = str(argv[0])
    explicit_path = "/" in argv0 or "\\" in argv0
    if explicit_path:
        exe_path = _parse_abs_path(argv0, f"{path}[0]")
    else:
        which_path = _CONTROLLED_PATH
        resolved_str = shutil.which(argv0, path=which_path)
        if not resolved_str:
            _fail(f"{path}[0]", "must resolve to an allowlisted executable")
        exe_path = Path(resolved_str)
    try:
        resolved = exe_path.resolve()
    except Exception:
        _fail(f"{path}[0]", "must resolve to an allowlisted executable")
    if not resolved.is_file():
        _fail(f"{path}[0]", "must resolve to a file")
    if not os.access(resolved, os.X_OK):
        _fail(f"{path}[0]", "must be executable")
    if explicit_path and not any(_is_relative_to(resolved, root) for root in _ALLOWED_ABS_EXEC_ROOTS):
        _fail(f"{path}[0]", "executable not allowlisted")
    if any(_is_relative_to(resolved, root) for root in _ALLOWED_COMMAND_ROOTS):
        return
    if _is_relative_to(resolved, _ALLOWED_COMMAND_USR_LOCAL):
        try:
            mode = resolved.stat().st_mode
        except OSError:
            _fail(f"{path}[0]", "must be executable")
        if mode & (stat.S_IWGRP | stat.S_IWOTH):
            _fail(f"{path}[0]", "must not be group/world-writable")
        return
    if explicit_path and any(_is_relative_to(resolved, root) for root in _ALLOWED_ABS_EXEC_ROOTS):
        return
    _fail(f"{path}[0]", "executable not allowlisted")


def load_spec(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            raw = json.load(handle)
    except FileNotFoundError as exc:
        raise ValidationError("spec: file not found") from exc
    except json.JSONDecodeError as exc:
        raise ValidationError("spec: invalid json") from exc
    if not isinstance(raw, dict):
        _fail("spec", "must be a JSON object")
    return raw


def validate_spec(raw: dict) -> FuzzSpec:
    if not isinstance(raw, dict):
        _fail("spec", "must be a JSON object")

    top_level = _validate_keys(
        raw,
        {
            "schema_version",
            "campaign_id",
            "description",
            "target",
            "seed",
            "mutations",
            "execution",
            "outputs",
        },
        (
            "schema_version",
            "campaign_id",
            "target",
            "seed",
            "mutations",
            "execution",
            "outputs",
        ),
        "",
    )

    schema_version = _require_string(top_level["schema_version"], "schema_version")
    if schema_version != SCHEMA_VERSION:
        _fail("schema_version", f"must equal {SCHEMA_VERSION}")

    campaign_id = _require_string(top_level["campaign_id"], "campaign_id")

    description = None
    if "description" in top_level:
        description = _require_string(top_level["description"], "description")

    target_obj = _require_object(top_level["target"], "target")
    has_command = "command" in target_obj
    if has_command:
        target_raw = _validate_keys(
            target_obj,
            {
                "engine",
                "agent_id",
                "work_root_base",
                "runtime_root",
                "engine_policy",
                "run_agent_script",
                "command",
                "timeout_s",
            },
            ("agent_id", "work_root_base", "command"),
            "target",
        )
    else:
        raise ValidationError("Adapters are not shipped in OSS. Use target.command.")

    engine = None
    if "engine" in target_raw:
        engine = _require_string(target_raw["engine"], "target.engine")

    agent_id = _require_string(target_raw["agent_id"], "target.agent_id")
    if agent_id == "":
        _fail("target.agent_id", "must not be empty")

    work_root_base = _parse_abs_path(target_raw["work_root_base"], "target.work_root_base")
    runtime_root = (
        _parse_abs_path(target_raw["runtime_root"], "target.runtime_root")
        if "runtime_root" in target_raw
        else None
    )
    engine_policy = (
        _parse_abs_path(target_raw["engine_policy"], "target.engine_policy")
        if "engine_policy" in target_raw
        else None
    )
    run_agent_script = (
        _parse_abs_path(target_raw["run_agent_script"], "target.run_agent_script")
        if "run_agent_script" in target_raw
        else None
    )

    command = None
    timeout_s = None
    if has_command:
        command = _validate_command_argv(target_raw["command"], "target.command")
        if "timeout_s" in target_raw:
            timeout_s = _require_number_gt_zero(target_raw["timeout_s"], "target.timeout_s")

    if runtime_root is not None:
        if _is_relative_to(work_root_base, runtime_root / "work"):
            _fail("target.work_root_base", "must not be under runtime_root/work")
        if _is_relative_to(work_root_base, runtime_root):
            _fail("target.work_root_base", "must not be under runtime_root")

    target = TargetSpec(
        work_root_base=work_root_base,
        agent_id=agent_id,
        runtime_root=runtime_root,
        engine_policy=engine_policy,
        run_agent_script=run_agent_script,
        engine=engine,
        command=command,
        timeout_s=timeout_s,
    )

    seed_raw = _validate_keys(
        top_level["seed"],
        {"path", "media_type", "sha256"},
        ("path",),
        "seed",
    )
    seed_path = _parse_abs_path(seed_raw["path"], "seed.path")
    if not seed_path.exists():
        _fail("seed.path", "path does not exist")

    media_type = None
    if "media_type" in seed_raw:
        media_type = _require_string(seed_raw["media_type"], "seed.media_type")

    sha256 = None
    if "sha256" in seed_raw:
        sha256 = _require_string(seed_raw["sha256"], "seed.sha256")
        if not _HEX64_RE.fullmatch(sha256):
            _fail("seed.sha256", "must be 64 hex characters")

    seed = SeedSpec(path=seed_path, media_type=media_type, sha256=sha256)

    mutations_raw = _validate_keys(
        top_level["mutations"],
        {"cases", "rng_seed", "max_bytes", "max_ops_per_case", "strategies"},
        ("cases",),
        "mutations",
    )
    cases = _require_int_gt_zero(mutations_raw["cases"], "mutations.cases")
    rng_seed = None
    if "rng_seed" in mutations_raw:
        rng_seed = _require_int(mutations_raw["rng_seed"], "mutations.rng_seed")
    max_bytes = None
    if "max_bytes" in mutations_raw:
        max_bytes = _require_int_gt_zero(mutations_raw["max_bytes"], "mutations.max_bytes")
    max_ops_per_case = 1
    if "max_ops_per_case" in mutations_raw:
        max_ops_per_case = _require_int_ge_zero(
            mutations_raw["max_ops_per_case"],
            "mutations.max_ops_per_case",
        )
    strategies = None
    if "strategies" in mutations_raw:
        strategies = _validate_mutation_strategies(
            mutations_raw["strategies"],
            "mutations.strategies",
        )

    mutations = MutationsSpec(
        cases=cases,
        rng_seed=rng_seed,
        max_bytes=max_bytes,
        max_ops_per_case=max_ops_per_case,
        strategies=strategies,
    )

    execution_raw = _validate_keys(
        top_level["execution"],
        {"work_root_mode", "env_overrides"},
        (),
        "execution",
    )

    work_root_mode = _DEFAULT_WORK_ROOT_MODE
    if "work_root_mode" in execution_raw:
        work_root_mode = _require_string(
            execution_raw["work_root_mode"],
            "execution.work_root_mode",
        )
        if work_root_mode not in _ALLOWED_WORK_ROOT_MODES:
            _fail("execution.work_root_mode", "must be one of per_run, shared")

    env_overrides = None
    if "env_overrides" in execution_raw:
        env_overrides_raw = _require_object(
            execution_raw["env_overrides"],
            "execution.env_overrides",
        )
        for key in env_overrides_raw.keys():
            if not isinstance(key, str):
                _fail("execution.env_overrides", "keys must be strings")
        env_overrides = {}
        for key in sorted(env_overrides_raw.keys()):
            value = env_overrides_raw[key]
            if key not in _ALLOWED_ENV_KEYS:
                _fail(f"execution.env_overrides.{key}", "not allowlisted")
            if not isinstance(value, str):
                _fail(f"execution.env_overrides.{key}", "must be a string")
            if key == "PYTHONUNBUFFERED" and value not in ("0", "1"):
                _fail(f"execution.env_overrides.{key}", 'must be "0" or "1"')
            env_overrides[key] = value

    execution = ExecutionSpec(
        work_root_mode=work_root_mode,
        env_overrides=env_overrides,
    )

    outputs_raw = _validate_keys(
        top_level["outputs"],
        {"input_dir", "out_dir", "eval_dir", "llmfuzz_dir"},
        ("out_dir", "eval_dir"),
        "outputs",
    )
    input_dir = None
    if "input_dir" in outputs_raw:
        input_dir = _validate_output_template(
            outputs_raw["input_dir"],
            "outputs.input_dir",
        )
    out_dir = _validate_output_template(outputs_raw["out_dir"], "outputs.out_dir")
    eval_dir = _validate_output_template(outputs_raw["eval_dir"], "outputs.eval_dir")
    llmfuzz_dir = None
    if "llmfuzz_dir" in outputs_raw:
        llmfuzz_dir = _validate_output_template(
            outputs_raw["llmfuzz_dir"],
            "outputs.llmfuzz_dir",
        )

    outputs = OutputsSpec(
        input_dir=input_dir,
        out_dir=out_dir,
        eval_dir=eval_dir,
        llmfuzz_dir=llmfuzz_dir,
    )

    return FuzzSpec(
        schema_version=schema_version,
        campaign_id=campaign_id,
        description=description,
        target=target,
        seed=seed,
        mutations=mutations,
        execution=execution,
        outputs=outputs,
    )


def collect_reserved_field_warnings(spec: FuzzSpec) -> list[str]:
    fields: list[str] = []
    if spec.execution.work_root_mode != _DEFAULT_WORK_ROOT_MODE:
        fields.append("execution.work_root_mode")
    if spec.outputs.input_dir is not None:
        if spec.outputs.input_dir != _DEFAULT_OUTPUT_TEMPLATES["input_dir"]:
            fields.append("outputs.input_dir")
    if spec.outputs.out_dir != _DEFAULT_OUTPUT_TEMPLATES["out_dir"]:
        fields.append("outputs.out_dir")
    if spec.outputs.eval_dir != _DEFAULT_OUTPUT_TEMPLATES["eval_dir"]:
        fields.append("outputs.eval_dir")
    if spec.outputs.llmfuzz_dir is not None:
        if spec.outputs.llmfuzz_dir != _DEFAULT_OUTPUT_TEMPLATES["llmfuzz_dir"]:
            fields.append("outputs.llmfuzz_dir")
    return fields
