# LLMFuzz Red Team

LLMFuzz Red Team uses a GPT-5.6-generated, validated adversarial corpus and deterministic machine-event invariants to produce replayable security-regression evidence for command-driven AI-agent targets.

> **Verified control result — same accepted corpus: 16 cases / 4 attack classes**
>
> | Control | PASS | FAIL | Critical failures | Failure clusters |
> | --- | ---: | ---: | ---: | ---: |
> | Vulnerable | 0 | 16 | 16 | 4 |
> | Fixed | 16 | 0 | 0 | 0 |
>
> **Comparison:** 16 critical failures resolved, 0 introduced, and 4 failure signatures removed.

## Supported platform

- Linux
- CPython 3.11 and 3.12

The intended judge distribution for `v0.2.0` is the prebuilt wheel attached to its GitHub Release.

## Prebuilt-wheel judge quickstart

The commands below install the `v0.2.0` release asset. They use CPython 3.11; substitute `python3.12` for `python3.11` to use the other supported interpreter.

```bash
python3.11 -m venv .venv
. .venv/bin/activate

python -m pip install \
  "https://github.com/Plutonus979/llmfuzz/releases/download/v0.2.0/plutonus_llmfuzz-0.2.0-py3-none-any.whl"

ROOT="$(mktemp -d)"

llmfuzz redteam run \
  --target vulnerable \
  --output "$ROOT/vulnerable"

llmfuzz redteam run \
  --target fixed \
  --output "$ROOT/fixed"

llmfuzz redteam report \
  --vulnerable-run "$ROOT/vulnerable" \
  --fixed-run "$ROOT/fixed" \
  --output "$ROOT/report"

cat "$ROOT/report/llmfuzz/redteam-comparison.md"
```

Network access may be required to download the wheel and its installation dependencies. After installation, this judge execution is offline: it requires no OpenAI API key, GPU, local model, or private LAB infrastructure. It uses the bundled accepted corpus and never falls back to generation.

## Expected result

The current source-tree judge flow produced these control-fixture results:

| Result | Vulnerable control | Fixed control |
| --- | ---: | ---: |
| Cases | 16 | 16 |
| PASS | 0 | 16 |
| FAIL | 16 | 0 |
| TIMEOUT | 0 | 0 |
| BLOCKED | 0 | 0 |
| Critical failures | 16 | 0 |
| Failure clusters | 4 | 0 |

The comparison resolved 16 critical failures, introduced 0, removed 4 failure signatures, and left 0 persistent or added signatures.

## How the system works

```text
optional bounded GPT-5.6 generation
→ strict local schema validation
→ canonical persistence and SHA-256 identity
→ offline execution through the command-target boundary
→ bounded machine-readable events
→ deterministic invariant evaluation
→ signatures and clustering
→ vulnerable-versus-fixed comparison
```

Generation is explicit, optional, and networked. The judge path instead replays the bundled accepted corpus deterministically and offline after installation. GPT-5.6 generates adversarial cases; it does not assign verdicts. Local deterministic invariants derive verdicts from validated machine-readable evidence.

## Four attack classes and synthetic control fixtures

The accepted corpus contains four cases in each of exactly four attack classes:

1. prompt injection;
2. secret exfiltration;
3. forbidden tool use;
4. approval bypass.

The included vulnerable and fixed targets are synthetic deterministic control fixtures, not production agents. They use synthetic secrets, tools, and protected actions; perform no destructive external action; require no network, GPU, or model; and emit bounded machine-readable events.

## GPT-5.6 Sol, Responses API, and Structured Outputs

Optional corpus generation uses GPT-5.6 Sol (`gpt-5.6-sol`) through the OpenAI Responses API. Structured Outputs constrain the provider response, and strict local validation is required before canonical persistence. The accepted corpus contains 16 canonically validated cases and is identified by SHA-256. Replay and verdict assignment remain local and deterministic: GPT-5.6 is not the final judge.

Generation is separate from the judge quickstart. From a source checkout, install the existing optional dependency extra and explicitly invoke generation:

```bash
python -m pip install -e '.[openai]'
# Set OPENAI_API_KEY through your normal secret-management workflow.
llmfuzz redteam generate \
  --cases 16 \
  --max-output-tokens 16384 \
  --output generated-corpus.json
```

Generation requires `OPENAI_API_KEY` and network access. Generated corpora are separately identifiable artifacts. The locked judge demonstration intentionally replays the bundled accepted corpus, and `redteam run` accepts only the exact accepted corpus identity. A freshly generated corpus therefore requires an explicit acceptance and promotion step before it can replace that locked judge corpus.

## AI-native development workflow and human-controlled decisions

I set the product direction, controlled scope and security boundaries, made acceptance decisions, and retained release ownership.

| Contributor | Role |
| --- | --- |
| Plutonus (me) | Product direction, scope and security boundaries, workflow orchestration, acceptance decisions, and release ownership |
| ChatGPT | Architecture and specification analysis, prompt drafting, decision support, and submission coordination |
| Codex | Repository inspection, implementation, testing, debugging, and release verification |
| Separate Codex review sessions | Independent challenge and review of implementation |
| GPT-5.6 Sol through the Responses API | Generation of the accepted structured 16-case adversarial corpus |

This attribution does not assign authorship percentages, and human-controlled acceptance and release decisions remain distinct from AI-assisted implementation and review.

## Pre-existing baseline versus Build Week delta

| Pre-existing before Build Week | Build Week Red Team delta |
| --- | --- |
| Deterministic byte mutation | GPT-5.6 Sol adversarial corpus generation |
| Command execution boundary | Structured Outputs and strict local validation |
| Artifact capture | Canonical persistence and SHA-256 identity |
| Legacy evaluator | Accepted bundled 16-case corpus |
| Campaign execution and triage | Semantic vulnerable/fixed control targets |
| v0.1.1 packaging | Machine-event invariant evaluation |
|  | Deterministic Red Team signatures and clustering |
|  | Vulnerable-versus-fixed comparison reporting |

The historical baseline is tag `build-week-2026-baseline`, peeled SHA `c9f387dd157da409a0c883727b3f0de6964594d8`. The original byte-fuzzing system and its v0.1.1 packaging predate Build Week.

## Security and privacy boundaries

- The judge path makes no live OpenAI call and requires no API key.
- The bundled corpus and judge artifacts contain no API key; demo fixtures contain no real secrets.
- Tools and protected actions in the demo targets are synthetic only.
- Verdict computation is local and deterministic.
- Target execution and output are bounded.
- Command execution uses the documented argv command boundary with `shell=False`.
- Canonical validation and conflict detection protect the expected evidence contract.
- SHA-256 supplies deterministic identity, not a cryptographic signature or signed provenance chain.
- This is not a digitally signed evidence-custody system and is not described as tamper-proof.

## Limitations and non-claims

- Linux only; CPython 3.11 and 3.12 only.
- The demonstration covers exactly four attack classes using synthetic control fixtures.
- Targets must be command-driven and emit the documented machine-event contract.
- There is no arbitrary-agent support claim and no comprehensive agent-security claim.
- The project does not claim to prevent every prompt injection.
- There is no zero-false-positive or zero-false-negative claim.
- There is no production-readiness or customer-adoption claim.
- Windows, WSL2, macOS, and other Python versions are not supported claims.
- There is no signed evidence-custody claim.

## Legacy LLMFuzz v0.1 functionality

The pre-existing LLMFuzz v0.1 command surface remains available: `validate`, `run`, `run-one`, `campaign`, `eval-run`, `triage-campaign`, and `replay`. It covers deterministic byte fuzzing, command execution, evaluation, artifact capture, and campaign triage. These capabilities are historical baseline functionality rather than Build Week Red Team additions.

## Release, license, and further documentation

- Current release version: `0.2.0`
- Distribution name: `plutonus-llmfuzz`
- CLI and import name: `llmfuzz`
- License: [Apache License 2.0](LICENSE)
- Build Week scope: [LLMFuzz Red Team scope v1](docs/build-week-2026/llmfuzz-red-team-scope.v1.md)
- Scope amendment: [LLMFuzz Red Team scope amendment v1.1](docs/build-week-2026/llmfuzz-red-team-scope-amendment.v1_1.md)
- Deterministic evaluator: [Phase D2 evaluator specification](docs/build-week-2026/llmfuzz-red-team-d2-evaluator-spec.v1.md)
- Reporting and comparison: [Phase D3 reporting specification](docs/build-week-2026/llmfuzz-red-team-d3-reporting-spec.v1.md)
