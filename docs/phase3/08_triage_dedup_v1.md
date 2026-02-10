# Triage + Dedup v1 (Campaign)

## What it does

`triage-campaign` produces a deterministic "triage view" over a campaign, grouped by:

- `verdict_eval`
- `signature_v1`

Cluster key is:

`cluster_key = "<verdict_eval>|<signature_v1>"`

## Where it writes artifacts

Triage artifacts are written under:

`<work_root_base>/llmfuzz/campaigns/<campaign_id>/triage/`

Artifacts:

- `triage/triage.json` (always)
- `triage/triage.md` (if `--write-md true`)

Optional side-effect (if `--patch-summary true` and `summary.json` exists):

- patches `<work_root_base>/llmfuzz/campaigns/<campaign_id>/summary.json`

## Example command

Invocation note:
- In a monorepo layout: `python3 -m llmfuzz ...`
- In standalone OSS repo: `python3 -m llmfuzz ...`

```
python -m llmfuzz triage-campaign --work-root-base <WORK_ROOT_BASE> --campaign-id <CAMPAIGN_ID>
```

## Ordering rules (deterministic)

Severity rank:

`FAIL > TIMEOUT > BLOCKED > DRY_RUN > PASS > UNKNOWN`

Sort keys for clusters:

1. severity rank (asc)
2. `count` (desc)
3. `first_case_index` (asc)
4. `cluster_key` (lex asc)

