# LLMFuzz Orchestrator v1

Note: v0.1 is supported on Linux (and WSL2 best-effort); Windows is not guaranteed.

## Canonical run layout

```
<work_root>/runs/<run_id>/
  exec/
    exec.json
    stdout.txt
    stderr.txt
  input/
    original.pdf
    original.seed.pdf
  llmfuzz/
    fuzzspec.json
    seed.json
    mutations.jsonl
    runner.stdout.txt
    runner.stderr.txt
    exec.json
  out/
  eval/
    failure_record.json
```

## Guaranteed artifacts

- `exec/exec.json`
- `exec/stdout.txt`
- `exec/stderr.txt`
- `input/original.pdf` (mutated input)
- `input/original.seed.pdf` (original seed)
- `llmfuzz/fuzzspec.json` (spec snapshot)
- `llmfuzz/seed.json`
- `llmfuzz/mutations.jsonl`
- `llmfuzz/runner.stdout.txt`
- `llmfuzz/runner.stderr.txt`
- `llmfuzz/exec.json` (compat: evaluator v1)
- `context.json`
- `eval/failure_record.json`

## Running

Invocation note:
- In a monorepo layout: `python3 -m llmfuzz ...`
- In standalone OSS repo: `python3 -m llmfuzz ...`

```
python3 -m llmfuzz validate --spec docs/phase3/examples/fuzzspec_command_v1.json
python3 -m llmfuzz run --spec docs/phase3/examples/fuzzspec_command_v1.json --case-index 0 [--run-id <ID>] [--dry-run]
```

Inspect exec artifacts: `<work_root>/runs/<run_id>/exec/exec.json`.

## Exit codes

- `0` = successful run (failure_record is written)
- `1` = internal error / not executable / not writable
- `2` = invalid spec

## Failure record

- `failure_record.json` is in the `eval/` directory: `<work_root>/runs/<run_id>/eval/failure_record.json`
- In `--dry-run` mode, `verdict` is `SKIPPED` if present in the enum; otherwise it remains `BLOCKED_POLICY` (for compatibility with the repo model).
