# LLMFuzz V0.1 Checkpoint

- Part 3 DONE
- Part 4 DONE
- Mutations contract (v0.1):
  - `mutations.cases` je obavezno polje (integer > 0)
  - `mutations.rng_seed` (opciono): deterministicki per-case seed = `rng_seed + case_index`; ako nije setovan, per-case seed = `case_index`
  - `mutations.max_bytes` (opciono): hard limit, izlaz se clamp-uje na `max_bytes`; ako je `max_bytes` manji od `len(seed_bytes)`, izlaz se truncates na `max_bytes`; default je neogranicen
  - `mutations.max_ops_per_case` (opciono): hard limit ops po case-u; `0` znaci no-op; default je 1 kada polje izostane
- Evaluator v1 preferira `exec/exec.json` + `exec/stdout.txt` + `exec/stderr.txt`, fallback na `llmfuzz/exec.json` + `llmfuzz/runner.*.txt`
- CRASH signature: `stderr_tail` ako postoji, inace tail `stderr.txt` (4096B) uz anti-empty sentinel
- Evaluator uvek upisuje `runs/<run_id>/llmfuzz/eval.json`
- Triage koristi iskljucivo `runs/<run_id>/llmfuzz/eval.json`
