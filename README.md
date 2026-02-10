#  llmfuzz v0.1.1

`llmfuzz` is a **command-driven fuzz / eval / triage tool** for LLM-agent-style targets (or any target you can invoke as a command). It runs one case or a small campaign, writes **deterministic, inspectable artifacts** under a work root, and supports deterministic evaluation + campaign triage. **v0.1 is intentionally minimal**: OSS runs use `target.command` (argv, no shell) and focus on a stable on-disk contract.

## Governance

- This project is public but centrally governed.
- PRs may be reviewed selectively; there is no obligation to merge.
- Safety: `llmfuzz` executes user-configured commands and is not a sandbox (run targets in a container/VM).

## Install (editable)

- Python **>= 3.11**

PyPI install:

```bash
pip install plutonus-llmfuzz
```

Note: The PyPI distribution is named `plutonus-llmfuzz` due to name availability.
The CLI and Python import remain `llmfuzz`.

Editable install (recommended for development):

```bash
pip install -e .
```

Standard install:

```bash
pip install .
```

## 60-second Quickstart

This repo ships runnable example specs in `docs/phase3/examples/`.
The default hello quickstart target is self-contained (pure Python) and does not require any external Accounting/LAB runtime.

```bash
# From the repo root
SPEC="docs/phase3/examples/fuzzspec_quickstart_hello_command.json"

mkdir -p /tmp/llmfuzz_quickstart
printf '%s\n' '{"hello":"llmfuzz quickstart"}' > /tmp/llmfuzz_quickstart/seed.json

llmfuzz validate --spec "$SPEC"

# run-one prints two lines:
#  1) the run directory path
#  2) the failure_record.json path
RUN_DIR="$(llmfuzz run-one --spec "$SPEC" | head -n 1)"
RUN_ID="$(basename "$RUN_DIR")"
WORK_ROOT_BASE="$(dirname "$(dirname "$RUN_DIR")")"

# Note: runs/<run_id>/llmfuzz/eval.json is written by eval-run (not by run-one).
# Evaluate the run (writes runs/<run_id>/llmfuzz/eval.json)
llmfuzz eval-run --work-root-base "$WORK_ROOT_BASE" --run-id "$RUN_ID"
ls "$RUN_DIR/llmfuzz/eval.json"
```

Next step (campaign + triage):

```bash
# Execute a small campaign (prints campaign_id then campaign_root)
CAMPAIGN_ID="$(llmfuzz campaign --spec "$SPEC" --cases 3 --exec | head -n 1)"

# triage-campaign writes artifacts under the campaign root printed by `llmfuzz campaign`.
# See docs/phase3/06_campaign_runner_v1.md for layout details.
llmfuzz triage-campaign --work-root-base "$WORK_ROOT_BASE" --campaign-id "$CAMPAIGN_ID"
```

## Artifact layout (`runs/<run_id>/...`)

Runs are written under `target.work_root_base` using a fixed layout in v0.1:

```text
<work_root_base>/runs/<run_id>/
  context.json
  exec/
    exec.json
    stdout.txt
    stderr.txt
  input/
    original.seed.pdf
    original.pdf
  out/
    # target-generated outputs (commonly *.json)
  eval/
    failure_record.json
  llmfuzz/
    fuzzspec.json
    seed.json
    mutations.jsonl
    exec.json
    runner.stdout.txt
    runner.stderr.txt
    eval.json
```

Notes:
- `exec/exec.json`, `exec/stdout.txt`, `exec/stderr.txt` are the canonical execution evidence.
- `llmfuzz/eval.json` is the canonical evaluation artifact (written by `llmfuzz eval-run`; it appears only after `eval-run`).
- `eval/failure_record.json` is written by the runner; `eval-run --patch-failure-record` can append eval fields to it.

## SECURITY NOTE (important)

`llmfuzz` executes the commands you put in the spec (`target.command`) and writes artifacts to the configured work root. Run targets in a **sandbox/container/VM**, avoid running against **untrusted binaries** on machines that have **secrets**, and treat produced artifacts (stdout/stderr, inputs/outputs, JSON reports) as **potentially sensitive**.

## Reserved fields + `--strict`

v0.1 accepts a small set of spec fields that are **reserved / not implemented** at runtime. When these fields are set to **non-default values**, `llmfuzz validate` emits warnings; `llmfuzz validate --strict` **fails** (exit code 2) instead.

Reserved fields checked by the v0.1 validator:
- `execution.work_root_mode` (default: `per_run`)
- `outputs.input_dir` (default: `runs/<run_id>/input`)
- `outputs.out_dir` (default: `runs/<run_id>/out`)
- `outputs.eval_dir` (default: `runs/<run_id>/eval`)
- `outputs.llmfuzz_dir` (default: `runs/<run_id>/llmfuzz`)

In v0.1, customization is done via `target.work_root_base`; the runtime ignores non-default values for the reserved fields above.

## Links / Further reading

- Evidence Pack v0.1 (Accounting harness replay proof): docs/llmfuzz/evidence/v0_1/ (tag: llmfuzz-evidence-v0.1)
- `docs/phase3/06_fuzzspec_v1.md`
- `docs/phase3/05_orchestrator_v1.md`
- `docs/phase3/07_evaluator_v1.md`
- `docs/phase3/08_triage_dedup_v1.md`
- `docs/phase3/06_campaign_runner_v1.md`

## Release

```bash
git tag -a v0.1.1 -m "llmfuzz v0.1.1"
git push --tags

# Optional sanity check:
python -m pip install -U build
python -m build
python -m venv .venv-wheel
. .venv-wheel/bin/activate
python -m pip install dist/*.whl
llmfuzz --help
python -m llmfuzz --help
```
