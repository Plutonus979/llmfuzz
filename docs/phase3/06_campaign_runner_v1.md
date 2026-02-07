# Campaign Runner v1

## CLI examples

Invocation note:
- In a monorepo layout: `python3 -m llmfuzz ...`
- In standalone OSS repo: `python3 -m llmfuzz ...`

Plan-only (default, without executing the target):

```
python3 -m llmfuzz campaign --spec <PATH/spec.json> --cases 20
```

Execution (exec) with a timeout override and resume:

```
python3 -m llmfuzz campaign --spec <PATH/spec.json> --cases 20 --exec --timeout-s 180 --stop-on FAIL,TIMEOUT --resume
```

Campaign with an explicit ID:

```
python3 -m llmfuzz campaign --spec <PATH/spec.json> --cases 20 --campaign-id s7_smoke
```

## Campaign layout (meta, outside `runs/`)

The campaign is written exclusively under `<work_root_base>`:

```
<work_root_base>/llmfuzz/campaigns/<campaign_id>/
  campaign.json
  cases.jsonl
  summary.json
  locks/
    campaign.lock
```

Each case still uses the canonical run layout:

```
<work_root_base>/runs/<run_id>/...
```

## Resume behavior

- `--resume` loads existing `cases.jsonl` and continues from the first `case_index` not yet recorded.
- It does not duplicate existing records: the same `case_index` will not be added a second time.
- If `runs/<run_id>/eval/failure_record.json` exists but `runs/<run_id>/context.json` does not, the case is considered **incomplete** and will be rerun (because `artifact_id`/`input_sha256` must come from `context.json`).

## Stop-on semantics

- `--stop-on` is a comma-separated list of verdicts; default `FAIL,TIMEOUT`.
- After a case record is written, if its `verdict` is in `stop-on`, the loop stops.

