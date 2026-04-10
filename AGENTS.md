## Implementation Economy Rule

All changes MUST use the minimum necessary code surface to achieve the required behavior.

- Prefer the smallest correct patch (fewest lines, files, branches, and abstractions).
- Optimize for net simplicity, explicit behavior, bounded work, and predictable performance.
- Avoid unnecessary layers, helpers, wrappers, or generalization.
- Reuse existing contracts and modules instead of duplicating logic.
- Eliminate obvious scaling risks (unbounded loops, O(n²) in hot paths, uncontrolled fan-out).

Constraints (non-negotiable):
- Do NOT sacrifice determinism, correctness, contract integrity, auditability, or fail-closed behavior.
- Do NOT use clever/condensed code that reduces readability or forensic clarity.
- Do NOT introduce hidden caching, retries, or side effects without explicit bounds and contracts.

Decision rule:
If two solutions are correct, choose the one with:
1) simpler design
2) smaller code surface
3) better performance/scaling characteristics

Codex must:
- attempt the smallest viable change first
- check for simpler alternatives before adding abstractions
- justify any non-trivial abstraction, cache, retry, or performance optimization
