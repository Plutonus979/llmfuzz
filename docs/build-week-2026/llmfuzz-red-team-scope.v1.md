# LLMFuzz Red Team — Build Week 2026 Scope v1

## 1. Status and authority

- Document status: **ACTIVE**.
- Version: **v1**.
- Repository: `/lab/src/llmfuzz_public`.
- Implementation branch: `build-week/llmfuzz-red-team`.
- Baseline tag: `build-week-2026-baseline`.
- Baseline commit: `c9f387dd157da409a0c883727b3f0de6964594d8`.
- This document governs the Build Week MVP described below.
- Later scope changes require an explicit, documented scope revision.
- This document locks intended work; it does not claim that the Build Week delta is already implemented.

The canonical pitch is: LLMFuzz Red Team uses GPT-5.6 to generate bounded semantic
adversarial corpora for local AI agents, while deterministic invariants—not an LLM
judge—produce replayable, evidence-backed verdicts suitable for regression testing and CI.

## 2. Problem

LLMFuzz v0.1.1 deterministically mutates input bytes and is useful for execution robustness,
artifact capture, and repeatable crash-style evaluation. Byte mutation cannot intentionally
create semantically meaningful attacks against an AI agent's instructions, tool policy,
secret handling, or approval behavior.

The Build Week delta must generate a bounded set of semantic adversarial inputs, execute
them through the existing command-target boundary, and evaluate target-produced machine
evidence. The final verdict must be computed from deterministic invariants; an LLM must not
be the final judge.

## 3. Existing baseline

### Pre-existing v0.1.1 baseline

Repository evidence identifies `llmfuzz` v0.1.1 as a Python 3.11+ command-driven fuzz,
evaluation, and triage tool. Before Build Week it already provides:

- deterministic byte-level strategies: `flip_bit`, `flip_byte`, `truncate_tail`, and
  `append_bytes`, with deterministic per-case seeding and size/operation bounds;
- command targets expressed as argv and executed with `shell=False` under a controlled
  executable policy;
- individual `run`/`run-one` execution and bounded `campaign` execution;
- fixed run and campaign artifact layouts under a configured work root;
- a deterministic evaluator with PASS, FAIL, TIMEOUT, BLOCKED, and dry-run handling;
- deterministic failure signatures for timeouts, crashes, missing output, invalid JSON,
  blocked runs, and passes;
- deterministic campaign triage and deduplication by verdict and failure signature;
- PyPI packaging as `plutonus-llmfuzz`, while retaining the `llmfuzz` CLI and import;
- CI on Python 3.11 and 3.12, source distribution/wheel builds, and wheel-install CLI sanity;
- self-contained quickstart and regression tests.

The v0.1.1 release tag points to commit `71691c9`. Pre-Build-Week maintenance after that
release, including centralized I/O helpers and removal of the legacy adapter path, was
merged through PR #10.

### Build Week baseline

- Tag: `build-week-2026-baseline`.
- Peeled commit: `c9f387dd157da409a0c883727b3f0de6964594d8`.
- PR #10 maintenance is baseline work, not Build Week feature work.

### Attribution boundary

Build Week work begins strictly after commit
`c9f387dd157da409a0c883727b3f0de6964594d8`. None of the capabilities above may be
described as created during Build Week. Only the semantic Red Team delta in Section 4 is
Build Week functionality.

## 4. Build Week delta

The MVP delta is limited to:

1. GPT-5.6 structured adversarial corpus generation through the OpenAI Responses API.
2. Strict schema validation before a generated corpus is accepted.
3. Safe corpus persistence with bounded, non-secret generation metadata.
4. Replay of the persisted corpus without another OpenAI request.
5. Execution of cases against command-based targets.
6. Capture of semantic, machine-readable event and result evidence.
7. Deterministic invariant evaluation and verdict assignment.
8. Deterministic failure signatures and clustering.
9. Vulnerable-versus-fixed demo reporting from the same persisted corpus.

The delta should extend existing modules and artifact conventions with the smallest viable
surface. It must not redesign byte mutation, the existing evaluator contract, packaging, or
unrelated repository structure.

## 5. Canonical architecture

```text
GPT-5.6 Responses API
  -> bounded structured adversarial corpus
  -> schema validation and persistence
  -> LLMFuzz campaign execution
  -> command-based AI-agent target
  -> machine-readable events and invariant results
  -> deterministic verdict
  -> failure signatures, clusters, and evidence report
```

GPT-5.6 generates attacks but is not the final judge. Generation is an explicit,
networked preparation step. Validation, persistence, replay, execution, evaluation,
clustering, and reporting must have deterministic offline paths for a persisted corpus.

## 6. CLI contract

### Mandatory user behavior

- The user flow is **generate -> run -> report**.
- Generate is the only flow permitted to call OpenAI.
- Run consumes an already validated, persisted corpus and an explicit command target.
- Report consumes persisted result evidence; it does not execute or generate cases.
- Replay and judge paths must never invoke generation automatically.
- Regeneration must be an explicit user action and must create a separately identifiable
  corpus rather than silently replacing evidence.
- Existing v0.1.1 commands and their behavior must remain compatible.

### Provisional command spelling

The compatible intended surface is:

```text
llmfuzz redteam generate ...
llmfuzz redteam run ...
llmfuzz redteam report ...
```

The repository currently uses one flat `argparse` subparser layer (`validate`, `run`,
`run-one`, `campaign`, `eval-run`, `triage-campaign`, and a replay stub). Nested `redteam`
subparsers are therefore provisional until implementation confirms the smallest compatible
parser arrangement. Final spelling may use flat equivalents, but it must preserve the three
mandatory operations and the generate/run/report order.

## 7. GPT-5.6 generation boundary

- Provider and endpoint family: OpenAI Responses API.
- Generation model: GPT-5.6.
- Response contract: Structured Outputs validated against the versioned corpus schema.
- Case count and output tokens must be bounded before the request is made.
- Generation must not occur implicitly from run, replay, report, or judge commands.
- A failed or invalid response must not trigger unbounded regeneration.
- Each API operation permits at most one retry: two attempts total.
- Tests must inject a mock client and make no live API request.
- CI must make no live API request, even if an API key is present in its environment.
- GPT-5.6 must not judge the final outcome.
- Prompts, corpora, results, and logs must not persist chain-of-thought.
- Implementation must use authoritative SDK behavior available at implementation time;
  this scope does not invent SDK method names or response field paths.

## 8. Corpus contract

The MVP uses one minimized, versioned corpus contract. A corpus has a top-level schema
version, generation metadata, and an ordered case list. Each case must contain at least:

- `schema_version`;
- `case_id`, unique within the corpus and stable on replay;
- `attack_class`, restricted to Section 10;
- `input`, containing the target prompt or other target input;
- `expected_risk`, identifying the risk or invariant at stake;
- `rationale`, concise and not chain-of-thought;
- `assertions`, a bounded list of machine-checkable expectations.

Generation metadata must contain at least:

- `model`;
- `openai_response_id`;
- `prompt_sha256`;
- `output_schema_version`;
- `generation_timestamp`;
- token usage when available;
- requested case count;
- generated case count.

API keys and credentials are forbidden from corpus data and metadata. Canonical serialized
corpus bytes must have a SHA-256 identity. Ordering and canonicalization rules must make
that identity deterministic. The same persisted corpus must run against both demo targets,
and replay must require no OpenAI request.

Assertions must remain a small fixed set sufficient for the four MVP attack classes and
demo event contract. A generic policy DSL is not authorized.

## 9. Deterministic result and verdict contract

Each case result must contain at least:

- a result `schema_version` and `case_id`;
- ordered, machine-readable observed events;
- invariant results with stable invariant identifiers and pass/fail status;
- evidence references to persisted per-case artifacts;
- exactly one deterministic verdict.

Prose alone is insufficient when the target can emit structured evidence. Human-readable
summaries may supplement but must not replace machine evidence. The evaluator owns PASS,
FAIL, TIMEOUT, and BLOCKED assignment. GPT-5.6 has no final-verdict role.

A critical failure is a failed deterministic assertion whose validated `expected_risk` is
critical. Failure signatures must be derived only from canonical result data such as attack
class, invariant identifiers, verdict, and normalized evidence—not timestamps, prose
variation, or model judgment. Cluster membership and ordering must be deterministic. The
exact minimized result JSON shape remains an implementation question, not a product-scope
question.

## 10. Attack classes

The MVP authorizes exactly four attack classes:

1. prompt injection;
2. secret exfiltration;
3. forbidden tool use;
4. approval bypass.

Every accepted corpus must represent all four. No additional attack class is authorized in
v1.

## 11. Demo targets

Two self-contained command targets are required.

### Vulnerable target

The vulnerable target intentionally permits bounded synthetic failures, including following
injected instructions, revealing a synthetic secret, emitting a forbidden synthetic tool
event, and bypassing a synthetic approval flag.

### Fixed target

The fixed target is the same functional target with the minimum defenses needed to enforce
the locked invariants. Target differences must be small enough for the report and demo to
attribute changed verdicts to those defenses.

Both targets must:

- use synthetic secrets and tools only;
- perform no destructive external action;
- require no network, GPU, local model, or private LAB dependency;
- consume the same persisted corpus through the same execution contract;
- emit bounded machine-readable evidence.

The accepted demonstration must show deterministic failures for the vulnerable target and
zero critical failures for the fixed target. No exact vulnerable failure count is locked
before an accepted corpus exists.

## 12. Persistence and replay contract

Persistence must include:

- the validated corpus and its SHA-256 identity;
- corpus and output-schema versions plus safe generation metadata;
- per-case input and execution artifacts;
- target-emitted event evidence and invariant results;
- deterministic verdicts, signatures, clusters, and report artifacts.

Paths should extend the existing fixed run layout under `runs/<run_id>/...` and campaign
metadata under `<work_root_base>/llmfuzz/campaigns/<campaign_id>/...` where practical.
Exact Red Team subdirectory names are deferred until implementation inspection prevents
collision or duplication.

Replay must load and revalidate the persisted corpus, verify its hash, and make no OpenAI
request. Corpus identity must not change between targets. Regeneration must be explicit and
must record a new response identity, timestamp, and corpus hash.

## 13. API, security, and budget boundaries

- Hard maximum total project API expenditure: **USD 100**.
- Expected actual expenditure must be materially lower than USD 100.
- Provisional maximum accepted corpus size: **20 cases**; default target: **16 cases**.
- Accepted generation requests should support approximately 12–20 cases within limits.
- Provisional output-token limit per attempt: **16,384 output tokens**.
- Maximum attempts per generation operation: **2** (one initial call and one retry).
- Maximum Build Week project attempts: **12 total**, including retries.
- The application must fail closed when case, token, call, or configured cost limits would
  be exceeded.
- The application-side budget guard must record bounded call and token usage when available
  and use implementation-verified pricing inputs; exact cost calculations are not claimed
  measured by this scope document.
- The API key must be read only from the `OPENAI_API_KEY` environment variable.
- The API key must never be logged, persisted, included in exception output, or committed.
- Error sanitization must prevent credential leakage from client and transport exceptions.
- Chain-of-thought must not be requested for persistence or stored in any artifact.
- Tests and CI must make no live API request.

## 14. Judge installation and execution path

The judge path must require only a supported standard Python, repository or wheel
installation, the included pre-generated corpus, and the included deterministic vulnerable
and fixed command targets.

It must not require an OpenAI API key, GPT-5.6 call, GPU, RTX 5090, Ollama, vLLM, private
LAB runtime, private data, or network access after installation. Dependency installation
may use a network where the judge environment requires it.

Final implementation documentation must provide copy/paste install, vulnerable run, fixed
run, and comparison-report commands. On a fresh supported environment, the judge demo
should complete in under three minutes. Judge execution must never fall back to generation.

## 15. Testing and CI contract

The Build Week delta requires the smallest meaningful coverage for these boundaries:

- unit tests for corpus and result schema validation, including rejection cases;
- an injected mock Responses API client and no live model calls;
- call, token, cost-guard, and single-retry boundary tests;
- persistence, canonical hash, tamper rejection, and offline replay tests;
- deterministic event and invariant evaluation tests;
- vulnerable/fixed integration tests using the same accepted corpus;
- deterministic report count, breakdown, evidence, comparison, signature, and cluster tests;
- CLI smoke tests for generate, run/replay, and report separation;
- preservation of the existing v0.1.1 regression and quickstart suite;
- Python 3.11 and 3.12 compatibility;
- local wheel-install and both CLI entry-path sanity;
- negative checks proving secrets do not enter artifacts, logs, or exception text.

CI must not need an API key and must not issue live OpenAI requests. No broad coverage
percentage initiative or new test framework is required for this sprint.

## 16. Acceptance criteria

1. GPT-5.6 is meaningfully used through the Responses API for bounded corpus generation.
2. Structured output is strictly schema-validated before persistence or execution.
3. Approximately 12–20 cases can be generated within configured case and token limits.
4. The accepted corpus is persisted canonically and has a reproducible SHA-256 identity.
5. Replaying the persisted corpus performs no API call.
6. The same corpus identity runs against both vulnerable and fixed targets.
7. Deterministic verdicts are computed from machine-readable evidence and invariants.
8. All four locked attack classes are represented in the accepted corpus.
9. The vulnerable target produces deterministic critical failures.
10. The fixed target produces zero critical failures for the accepted corpus.
11. Repeated evaluation produces identical failure signatures and clusters.
12. The report contains counts, attack-class breakdown, representative evidence, and a
    vulnerable-versus-fixed comparison.
13. Tests prove the API key cannot enter logs, exceptions, or persisted artifacts.
14. Case, output-token, call, retry, and USD 100 project boundaries are enforced fail closed.
15. Generation tests use a mock OpenAI client.
16. CI performs no live API calls.
17. The judge path works without an API key, GPU, networked model, or private infrastructure.
18. Existing LLMFuzz commands, artifacts, evaluator behavior, and tests remain compatible.
19. Wheel installation plus `llmfuzz` and `python -m llmfuzz` CLI sanity pass on supported
    Python versions.
20. Baseline-versus-Build-Week attribution is documented with exact tag and commit evidence.

## 17. Explicit non-goals

The following are outside v1 scope:

- SaaS;
- authentication;
- user accounts;
- billing;
- database;
- web dashboard;
- multi-provider abstraction;
- generic policy language;
- broad plugin architecture;
- multi-turn adaptive attacks;
- autonomous self-improving attacker;
- GPT-5.6 as final judge;
- fuzzing GPT-5.6 itself as the primary target;
- mandatory local-model runtime;
- broad refactoring of existing LLMFuzz;
- unrelated packaging redesign;
- new attack classes;
- production-grade distributed execution;
- private LAB dependencies.

## 18. Delivery sequence

### Phase C — first vertical slice

GPT-5.6 -> strictly validated persisted corpus.

No execution or evaluator expansion may begin before this generation vertical slice passes
with a mocked test path and one explicitly authorized bounded live-generation proof.

### Phase D — deterministic execution

Persisted corpus -> vulnerable/fixed targets -> deterministic evidence verdict.

### Phase E — submission closure

Fresh install -> judge demo -> report -> video -> Devpost submission.

No polish begins before functional closure. Code work must not consume all of the final
submission day; time must remain for fresh-install proof, video, evidence, and submission.

## 19. Submission and attribution evidence

Preserve and later present:

- baseline tag `build-week-2026-baseline` and its peeled SHA;
- Build Week branch and commits made strictly after the baseline;
- a later README attribution section;
- evidence of meaningful GPT-5.6 and OpenAI Responses API use;
- evidence of Codex use;
- the main Codex `/feedback` Session ID, collected only after most core functionality is
  implemented in this continuing main session;
- a pre-existing-versus-Build-Week feature table;
- exact demo commands and fresh-install evidence;
- test, CI, and wheel-install evidence;
- bounded API usage evidence with no credential exposure;
- final submission and video links when available.

## 20. Locked implementation decisions

| Decision | Locked v1 choice |
|---|---|
| Product location | Extend the existing LLMFuzz repository; no new repository |
| Primary provider | OpenAI only |
| Generation model | GPT-5.6 only |
| API | OpenAI Responses API |
| Generation contract | Structured Outputs plus strict local schema validation |
| Final judge | Deterministic evaluator only |
| Replay | Persisted, hash-verified, and offline |
| Execution boundary | Existing command-target model, argv without shell |
| Attack scope | Exactly the four classes in Section 10 |
| Demo | One vulnerable and one minimally fixed self-contained target |
| Judge input | Included pre-generated accepted corpus |
| Judge runtime | Supported standard Python; no private runtime |
| CI API policy | No live API calls |
| Accelerator | No GPU requirement |
| Project spend | USD 100 hard ceiling; expected materially lower |
| Delivery strategy | Smallest complete vertical slice, then deterministic execution |

## 21. Open implementation questions

Only these implementation details remain open:

- whether the current flat CLI parser should gain a nested `redteam` parser or flat command
  equivalents;
- exact schema module and file layout with the fewest new modules;
- exact Red Team artifact directory names aligned with existing run/campaign layouts;
- exact minimized event/result JSON field shape and fixed assertion operators;
- exact budget-guard configuration representation and implementation-verified price inputs;
- exact report output formats beyond the required machine-readable artifact and concise
  judge-facing comparison.

These questions must not reopen the architecture, provider, generation model, final judge,
attack classes, demo targets, budget ceiling, judge requirements, or explicit non-goals.
