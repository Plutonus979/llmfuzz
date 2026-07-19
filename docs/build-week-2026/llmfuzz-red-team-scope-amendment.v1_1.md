# LLMFuzz Red Team — Build Week 2026 Scope Amendment v1.1

## 1. Status and authority

- Status: **ACTIVE**.
- Version: **v1.1 amendment**.
- Base scope: `llmfuzz-red-team-scope.v1.md`.

This amendment supersedes only the budget and aggregate-attempt provisions identified
below. All other v1 architecture, provider, model, attack classes, judge requirements,
delivery order, and non-goals remain authoritative. This is a scope correction based on
implementation economy and the actual Build Week operating model.

## 2. Superseded provisions

This amendment supersedes these interpretations of the v1 scope:

- Section 13: the maximum of 12 Build Week project attempts total, application-wide
  aggregate attempt enforcement, and a cross-process interpretation of project cost state.
- Acceptance criterion 14: project-wide call enforcement when interpreted as requiring a
  durable cross-process ledger.
- Section 21: budget-guard configuration as an open implementation question, insofar as it
  implied persistent aggregate project state.

It does not alter the maximum two attempts per explicit generation operation, 12–20 case
range, maximum 16,384 output tokens, per-request and per-operation validation, USD 100
application hard ceiling, secret handling, or no-live-API test policy.

## 3. Revised authoritative contract

Each explicit generation operation permits at most two attempts: one initial request and
at most one retry.

The application validates case count, output tokens, request usage, and worst-case cost
before or during the operation through the existing provider-neutral C2 boundary. The CLI
does not claim to enforce a durable aggregate attempt counter across processes, machines,
clones, installations, or repository states.

Every live generation is separately and explicitly operator-authorized. The configured
OpenAI project hard spend limit is the authoritative aggregate financial boundary for Build
Week API use. Observed token and estimated cost evidence is preserved in the generation
result and accepted corpus metadata when available. No cross-process durable budget ledger
is required for the MVP.

## 4. Evidence and local state

`/lab/.llmfuzz_public/` may later hold private operator-owned submission evidence. It is
outside the repository and outside the judge and product runtime contract. C3 does not
create or depend on this directory. Its absence, deletion, or corruption must neither
enable nor block generation.

C3 must not store an API key, prompt, corpus body, raw provider response, or exception in
that optional location.

## 5. Acceptance impact

Case, output-token, per-operation call/retry, request-usage, and per-operation configured
cost boundaries are enforced fail closed. Aggregate spend is bounded by the provider-side
project hard limit and explicit operator authorization.

## 6. Non-goal

A crash-durable, cross-process financial ledger is not part of the MVP.
