# Evaluator v1

## What it does

Evaluator v1 deterministically computes:

- `verdict` (PASS/FAIL/TIMEOUT/BLOCKED/DRY_RUN)
- `signature_v1` (per the rules below)

Based on existing run artifacts under `runs/<run_id>/...`.

## Where it writes artifacts

Always writes:

```
runs/<run_id>/llmfuzz/eval.json
```

Optionally (only with `--patch-failure-record`) appends:

```
runs/<run_id>/eval/failure_record.json
```

Does not write anything under `runtime_root`.

## Exec evidence sources (priority)

Prefers canonical paths:

- `runs/<run_id>/exec/exec.json`
- `runs/<run_id>/exec/stdout.txt`
- `runs/<run_id>/exec/stderr.txt`

Legacy fallback:

- `runs/<run_id>/llmfuzz/exec.json`
- `runs/<run_id>/llmfuzz/runner.stdout.txt`
- `runs/<run_id>/llmfuzz/runner.stderr.txt`

If `exec.json` does not exist in either location, the evaluator still deterministically writes
`runs/<run_id>/llmfuzz/eval.json` without crashing.

## Rules for `signature_v1`

- TIMEOUT: `TIMEOUT:<timeout_s>` (or `TIMEOUT` if unknown)
- Crash (exit_code != 0): `CRASH:<hash16>` where `hash16` is sha256 over normalized `stderr_tail`
  (absolute paths -> `<PATH>`, `run_id` -> `<RUN_ID>`, whitespace collapse).
  - If `stderr_tail` exists and is non-empty, use that content.
  - Otherwise take the tail from `stderr.txt` (last 4096 bytes), then normalize it.
  - If `stderr.txt` exists and is non-empty, but the normalized tail becomes empty, use the
    `<stderr-nonempty>` sentinel.
  - If `stderr.txt` does not exist or is empty, use the `<no-stderr>` sentinel.
- Missing outputs: `OUT_MISSING:<hash16>` (sha256 over a deterministic list of missing keys)
- Invalid JSON: `JSON_BAD:<basename>:<ErrorType>`
- PASS: `PASS`
- DRY_RUN: `DRY_RUN`
- BLOCKED: `BLOCKED`

## How to run

Invocation note:
- In a monorepo layout: `python3 -m llmfuzz ...`
- In standalone OSS repo: `python3 -m llmfuzz ...`

```
python -m llmfuzz eval-run --work-root-base <WORK_ROOT_BASE> --run-id <run_id>
```

With failure record patching:

```
python -m llmfuzz eval-run --work-root-base <WORK_ROOT_BASE> --run-id <run_id> --patch-failure-record
```

