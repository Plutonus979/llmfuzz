# Evidence Pack v0.1 (LLMFuzz + Accounting harness)

## Claim

Given this repo at a specific commit and this evidence pack's inputs, running `commands.sh` produces two independent runs of the **same** LLMFuzz case (same spec + `case-index=0`) against the existing **Accounting** harness, and the resulting `signature_v1` values are **equal** across the two runs.

## Non-goals

- This pack does not prove fuzzing effectiveness or coverage.
- This pack does not claim any particular `verdict` (PASS/FAIL/TIMEOUT/BLOCKED); it only asserts **replay stability** of `signature_v1` for the chosen case.
- This pack does not modify or patch any runtime/service files and does not change any core code.

## Reproduce (exact commands)

From repo root:

```bash
cd /home/lab/work/agent-lab
bash docs/llmfuzz/evidence/v0_1/commands.sh
```

Optional environment overrides (defaults are chosen to match the existing Accounting harness example spec shape):

```bash
cd /home/lab/work/agent-lab
LLMFUZZ_EVIDENCE_RUNTIME_ROOT="/home/lab/agent/runtime/accounting" \
LLMFUZZ_EVIDENCE_WORK_ROOT_BASE="/home/lab/agent/work/llmfuzz/evidence_pack_v0_1" \
LLMFUZZ_EVIDENCE_AGENT_ID="parser_stub" \
bash docs/llmfuzz/evidence/v0_1/commands.sh
```

## What to inspect

The script prints (and records) the absolute run directories for both runs. Inspect:

- `<run_dir>/llmfuzz/eval.json` (created by `eval-run`; contains `verdict` + `signature_v1`)
- `<run_dir>/eval/failure_record.json`
- `<run_dir>/exec/exec.json`, `<run_dir>/exec/stdout.txt`, `<run_dir>/exec/stderr.txt`
- `<run_dir>/out/` (contains at least `accounting_harness_result.json` copied by the wrapper step)

Local evidence-pack artifacts written by the script:

- `docs/llmfuzz/evidence/v0_1/provenance.v0_1.txt`
- `docs/llmfuzz/evidence/v0_1/sha256sums.v0_1.txt`
- `docs/llmfuzz/evidence/v0_1/_rendered_fuzzspec.v0_1.json` (absolute-path spec used for the run)

## Inputs

- `docs/llmfuzz/evidence/v0_1/inputs/seed.pdf` is a placeholder seed file (bytes-only; not a curated PDF corpus).
- `docs/llmfuzz/evidence/v0_1/inputs/fuzzspec.json` is a template. `commands.sh` renders it into an absolute-path spec before running.

