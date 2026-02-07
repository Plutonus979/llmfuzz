# FuzzSpec v1 (llmfuzz.fuzzspec.v1) — product contract

This document locks **FuzzSpec v1** as a stable, runtime-agnostic contract between users (spec authors) and the **LLMFuzz engine** (spec consumers).

FuzzSpec is a **declarative intent specification**: it describes what to fuzz (target), what it starts from (seed), how variations are generated (mutations), how the workspace is isolated (execution), and where artifacts are expected (outputs). FuzzSpec **does not execute anything**.

## Normative dictionary

The following words have normative meaning: **MUST**, **MUST NOT**, **SHOULD**, **MAY**.

## Purpose

- FuzzSpec v1 is a **product interface**: a stable format the engine can load, validate (schema + fail-fast rules), and turn into a concrete fuzz plan.
- FuzzSpec v1 allows the LLMFuzz engine to be **logically decoupled** from the LAB repository: the spec talks about target paths and parameters, without assumptions about execution or supporting tools.

## Conceptual model

FuzzSpec models a fuzzing campaign through the following flow:

- **campaign**: campaign identity (and optional description).
- **target**: base work root (`work_root_base`) + command argv (`command`) for OSS runs.
- **seed**: the input file that serves as the starting point for mutations.
- **mutations**: case count and limiters (rng_seed, max_bytes, max_ops_per_case).
- **execution**: declarative work-root mode choice and minimal allowlist env overrides.
- **outputs**: templates for locations where the engine expects run-scoped artifacts.

## Top-level structure

FuzzSpec v1 is a JSON object with the following top-level fields:

- `schema_version` (required)
- `campaign_id` (required)
- `description` (optional)
- `target` (required)
- `seed` (required)
- `mutations` (required)
- `execution` (required)
- `outputs` (required)

JSON Schema reference: `docs/phase3/schemas/llmfuzz_fuzzspec.v1.schema.json`.

## Field semantics (by section)

### `schema_version`

- Type: string
- Semantics: identifies the contract version.
- Value: MUST equal `"llmfuzz.fuzzspec.v1"`.

### `campaign_id`

- Type: string
- Semantics: stable campaign identifier (e.g., for tying artifacts, telemetry, or comparing results).
- Constraints: SHOULD be short and stable; the engine MAY use it as a label.

### `description` (optional)

- Type: string
- Semantics: human-readable campaign description; no machine semantics.

### `target`

`target` describes the environment in which the engine (outside this contract) would run the fuzz campaign.

Required fields (OSS):

- `target.agent_id` (string)
  - Semantics: target agent/flow identifier (e.g., `"intake_classifier"`).
- `target.work_root_base` (string, absolute path)
  - Semantics: root directory under which the engine organizes run-scoped working directories.
- `target.command` (array of strings, non-empty)
  - Semantics: command to run as an argv list (no shell).

Optional:

- `target.timeout_s` (number, \(> 0\)): timeout in seconds for `target.command` (default: 30).

OSS note (adapters):

- Adapters are not shipped in OSS. If `target.command` is missing, the validator rejects the spec.
- `target.command[0]` MAY be an absolute path or a bare executable name (e.g., `"python3"`), but it MUST resolve to an allowlisted executable (argv-based, no shell).

### `seed`

Required fields:

- `seed.path` (string, absolute path)
  - Semantics: input file to start from. The engine treats it as a byte source (it does not have to be a valid PDF).

Optional:

- `seed.media_type` (string): e.g., `"application/pdf"`. Informational.

### `mutations`

Required fields:

- `mutations.cases` (integer, \(> 0\))
  - Semantics: number of cases (iterations) the engine plans to generate.

Optional:

- `mutations.rng_seed` (integer)
  - Semantics: base seed for deterministic generation. When set, per-case seed = `rng_seed + case_index`.
- `mutations.max_bytes` (integer, \(> 0\))
  - Semantics: hard limit on output length; the engine MUST clamp to `max_bytes` after mutations. If `max_bytes` is less than `len(seed_bytes)`, the output is truncated to `max_bytes`.
- `mutations.max_ops_per_case` (integer, \(\>= 0\))
  - Semantics: hard limit on the number of mutation operations per case. `0` means no-op (no mutations), only clamp if `max_bytes` is set. If omitted, the default limit is 1.

Note: If `mutations.rng_seed` is not set, the default per-case seed is `case_index` (deterministic). If `mutations.max_bytes` is not set, the limit is unbounded.

### `execution`

This section describes declarative execution preferences, without defining any invocation.

- `execution.work_root_mode` (optional; default: `"per_run"`)
  - Allowed values:
    - `"per_run"`: the engine organizes isolated run directories (e.g., `runs/<run_id>/...`) under `target.work_root_base`.
    - `"shared"`: the engine MAY use a shared workspace under `target.work_root_base` (no isolation guarantee).
  - Note (v0.1): `execution.work_root_mode` is RESERVED / NOT IMPLEMENTED; the runtime ignores it. If the value is non-default, the validator emits a warning; in strict mode it may be rejected.
- `execution.env_overrides` (optional)
  - Semantics: minimal allowlisted set of env overrides the engine MAY apply. In v1 the allowlist is intentionally narrow.
  - Allowed keys (v1): only `PYTHONUNBUFFERED` (string value `"0"` or `"1"`).

### `outputs`

`outputs` defines **run-relative template string** locations for run-scoped artifacts.

- All `outputs.*` fields are **run-relative templates**, not absolute paths.
- A run-relative template is interpreted as a path **relative to `target.work_root_base`**.
- The template MAY contain the `<run_id>` placeholder (literal token), which the engine MAY replace with its run identifier.
- Note (v0.1): `outputs.*` are RESERVED / NOT IMPLEMENTED; the runtime ignores these values and uses a fixed layout under `<work_root_base>/runs/<run_id>/...` (e.g., `input/`, `out/`, `eval/`, `llmfuzz/`). Customization is done via `target.work_root_base`, not via `outputs` templates.

Required fields:

- `outputs.out_dir` (string, run-relative template)
  - Semantics: directory for primary outputs per run.
- `outputs.eval_dir` (string, run-relative template)
  - Semantics: directory for evaluation/reports per run.

Optional:

- `outputs.input_dir` (string, run-relative template): directory for run-scoped input.
- `outputs.llmfuzz_dir` (string, run-relative template): directory for engine-specific artifacts.

## FAIL-FAST rules (normative)

The engine (or validator) MUST reject the spec before any further interpretation if any of the following holds:

1) `schema_version` is not exactly `"llmfuzz.fuzzspec.v1"`.
2) Any required field (top-level or inside required objects) is missing.
3) The following fields are not absolute paths (MUST start with `/`):
   - `seed.path`
   - `target.work_root_base`
4) If `target.runtime_root` exists, `target.work_root_base` is under `target.runtime_root`.
   - This check MUST be done on normalized realpath values (resolving symlinks) where possible.
   - Note: this is a **cross-field** constraint that JSON Schema cannot reliably enforce; therefore it is defined here as fail-fast.
5) `mutations.cases` is not strictly greater than 0.
6) `mutations.max_bytes` exists but is not strictly greater than 0.
7) `mutations.max_ops_per_case` exists but is less than 0.
8) `outputs.*` are not run-relative template strings (e.g., any `outputs.*` starts with `/`).

## Non-goals (out of scope)

- FuzzSpec **does not execute anything** and does not define any runtime call or invocation.
- FuzzSpec does not describe a UI or API.
- FuzzSpec does not guarantee that `seed` is a valid PDF (or any valid format); seed is a byte input.
- FuzzSpec is not a runtime config file for a service; it is a product intent specification for a fuzz campaign.
- FuzzSpec does not define engine internal logic (planning, scheduling, replay), beyond minimal fail-fast constraints, determinism when `mutations.rng_seed` is set, and field semantics.

## Contract stability

Any incompatible change in structure or semantics requires a new `schema_version` value. The engine and user MUST treat `"llmfuzz.fuzzspec.v1"` as a locked contract.

