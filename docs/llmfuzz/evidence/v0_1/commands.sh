#!/usr/bin/env bash
set -euo pipefail

HERE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${HERE_DIR}/../../../../" && pwd)"

TEMPLATE_SPEC="${HERE_DIR}/inputs/fuzzspec.json"
SEED_PATH="${HERE_DIR}/inputs/seed.pdf"
RENDERED_SPEC="${HERE_DIR}/_rendered_fuzzspec.v0_1.json"
PROVENANCE_PATH="${HERE_DIR}/provenance.v0_1.txt"
SHA256SUMS_PATH="${HERE_DIR}/sha256sums.v0_1.txt"

RUNTIME_ROOT="${LLMFUZZ_EVIDENCE_RUNTIME_ROOT:-}"
WORK_ROOT_BASE="${LLMFUZZ_EVIDENCE_WORK_ROOT_BASE:-/tmp/llmfuzz_evidence_v0_1}"
AGENT_ID="${LLMFUZZ_EVIDENCE_AGENT_ID:-parser_stub}"

HARNESS_PATH="${LLMFUZZ_EVIDENCE_HARNESS_PATH:-}"

if test -z "${RUNTIME_ROOT}"; then
  echo "ERROR: LLMFUZZ_EVIDENCE_RUNTIME_ROOT is required (path to Accounting runtime root)" >&2
  exit 2
fi
if ! test -d "${RUNTIME_ROOT}"; then
  echo "ERROR: runtime root does not exist or is not a directory: ${RUNTIME_ROOT}" >&2
  exit 2
fi
if test -z "${HARNESS_PATH}"; then
  echo "ERROR: LLMFUZZ_EVIDENCE_HARNESS_PATH is required (path to accounting_agent_harness_v1.py)" >&2
  exit 2
fi
if ! test -f "${HARNESS_PATH}"; then
  echo "ERROR: harness path does not exist or is not a file: ${HARNESS_PATH}" >&2
  exit 2
fi

RUN_ID_1="evidencepack_v0_1_run1"
RUN_ID_2="evidencepack_v0_1_run2"

_utc_now() {
  python3 -c 'from datetime import datetime, timezone; print(datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))'
}

{
  echo "created_at_utc=$(_utc_now)"
  echo "repo_root=${REPO_ROOT}"
  echo "repo_commit=$(git -C "${REPO_ROOT}" rev-parse HEAD)"
  echo "python=$(python3 -V 2>&1 || true)"
  echo "uname=$(uname -a 2>&1 || true)"
  echo "pip_freeze_begin"
  python3 -m pip freeze 2>&1 || true
  echo "pip_freeze_end"
} | tee "${PROVENANCE_PATH}"

export HERE_DIR TEMPLATE_SPEC RENDERED_SPEC REPO_ROOT RUNTIME_ROOT WORK_ROOT_BASE AGENT_ID HARNESS_PATH

python3 - <<'PY'
import json
import os
from pathlib import Path

here_dir = Path(os.environ["HERE_DIR"]).resolve()
template_spec = Path(os.environ["TEMPLATE_SPEC"]).resolve()
rendered_spec = Path(os.environ["RENDERED_SPEC"]).resolve()
repo_root = Path(os.environ["REPO_ROOT"]).resolve()
runtime_root = Path(os.environ["RUNTIME_ROOT"]).resolve()
work_root_base = Path(os.environ["WORK_ROOT_BASE"]).resolve()
agent_id = os.environ["AGENT_ID"]
harness_path = Path(os.environ["HARNESS_PATH"]).resolve()
seed_path = (here_dir / "inputs" / "seed.pdf").resolve()

raw_text = template_spec.read_text(encoding="utf-8")
raw_text = raw_text.replace("__REPO_ROOT__", str(repo_root))
raw_text = raw_text.replace("__RUNTIME_ROOT__", str(runtime_root))
raw_text = raw_text.replace("__WORK_ROOT_BASE__", str(work_root_base))
raw_text = raw_text.replace("__AGENT_ID__", str(agent_id))
raw_text = raw_text.replace("__HARNESS_PATH__", str(harness_path))
raw_text = raw_text.replace("__SEED_PATH__", str(seed_path))

obj = json.loads(raw_text)
rendered_spec.write_text(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

if not str(work_root_base).startswith("/"):
    raise SystemExit("render: WORK_ROOT_BASE must be absolute")
if not str(seed_path).startswith("/") or not seed_path.exists():
    raise SystemExit("render: seed path must exist and be absolute")
PY

python3 -m llmfuzz validate --spec "${RENDERED_SPEC}"

EXPECTED_RUN_DIR_1="${WORK_ROOT_BASE}/runs/${RUN_ID_1}"
if test -e "${EXPECTED_RUN_DIR_1}"; then
  echo "ERROR: evidence run dir already exists (refusing to reuse): ${EXPECTED_RUN_DIR_1}" >&2
  exit 2
fi

RUN_OUTPUT_1="$(python3 -m llmfuzz run --spec "${RENDERED_SPEC}" --case-index 0 --run-id "${RUN_ID_1}")"
printf '%s\n' "${RUN_OUTPUT_1}" > "${HERE_DIR}/run1.output.txt"
RUN_DIR_1="$(python3 -c 'import sys; print(sys.stdin.read().splitlines()[0].strip())' <<<"${RUN_OUTPUT_1}")"
FAILURE_RECORD_1="$(python3 -c 'import sys; lines=sys.stdin.read().splitlines(); print(lines[1].strip() if len(lines)>1 else "")' <<<"${RUN_OUTPUT_1}")"

python3 -c 'import os,sys; p=sys.argv[1]; 
import pathlib; 
pp=pathlib.Path(p); 
assert pp.is_absolute(), f"run_dir not absolute: {p}"; 
assert pp.exists() and pp.is_dir(), f"run_dir missing: {p}"' "${RUN_DIR_1}"

python3 -m llmfuzz eval-run --work-root-base "${WORK_ROOT_BASE}" --run-id "${RUN_ID_1}" >/dev/null
test -f "${RUN_DIR_1}/llmfuzz/eval.json"

SIG_1="$(python3 -c 'import json,sys; p=sys.argv[1]; obj=json.load(open(p,"r",encoding="utf-8")); print(str(obj.get("signature_v1","")))' "${RUN_DIR_1}/llmfuzz/eval.json")"

EXPECTED_RUN_DIR_2="${WORK_ROOT_BASE}/runs/${RUN_ID_2}"
if test -e "${EXPECTED_RUN_DIR_2}"; then
  echo "ERROR: evidence run dir already exists (refusing to reuse): ${EXPECTED_RUN_DIR_2}" >&2
  exit 2
fi

RUN_OUTPUT_2="$(python3 -m llmfuzz run --spec "${RENDERED_SPEC}" --case-index 0 --run-id "${RUN_ID_2}")"
printf '%s\n' "${RUN_OUTPUT_2}" > "${HERE_DIR}/run2.output.txt"
RUN_DIR_2="$(python3 -c 'import sys; print(sys.stdin.read().splitlines()[0].strip())' <<<"${RUN_OUTPUT_2}")"
FAILURE_RECORD_2="$(python3 -c 'import sys; lines=sys.stdin.read().splitlines(); print(lines[1].strip() if len(lines)>1 else "")' <<<"${RUN_OUTPUT_2}")"

python3 -c 'import os,sys; p=sys.argv[1]; 
import pathlib; 
pp=pathlib.Path(p); 
assert pp.is_absolute(), f"run_dir not absolute: {p}"; 
assert pp.exists() and pp.is_dir(), f"run_dir missing: {p}"' "${RUN_DIR_2}"

python3 -m llmfuzz eval-run --work-root-base "${WORK_ROOT_BASE}" --run-id "${RUN_ID_2}" >/dev/null
test -f "${RUN_DIR_2}/llmfuzz/eval.json"

SIG_2="$(python3 -c 'import json,sys; p=sys.argv[1]; obj=json.load(open(p,"r",encoding="utf-8")); print(str(obj.get("signature_v1","")))' "${RUN_DIR_2}/llmfuzz/eval.json")"

export SIG_1 SIG_2

python3 - <<'PY'
import os
sig1 = os.environ["SIG_1"].strip()
sig2 = os.environ["SIG_2"].strip()
if sig1 != sig2:
    raise SystemExit(f"signature_v1 mismatch:\n  run1={sig1}\n  run2={sig2}")
print(f"OK: signature_v1 equal: {sig1}")
PY

{
  echo "# sha256sums.v0_1.txt"
  echo "# created_at_utc=$(_utc_now)"
  echo "# repo_commit=$(git -C "${REPO_ROOT}" rev-parse HEAD)"
  sha256sum -- "${SEED_PATH}"
  sha256sum -- "${RENDERED_SPEC}"
  sha256sum -- "${RUN_DIR_1}/llmfuzz/eval.json"
  if test -n "${FAILURE_RECORD_1}" && test -f "${FAILURE_RECORD_1}"; then
    sha256sum -- "${FAILURE_RECORD_1}"
  fi
  sha256sum -- "${RUN_DIR_2}/llmfuzz/eval.json"
  if test -n "${FAILURE_RECORD_2}" && test -f "${FAILURE_RECORD_2}"; then
    sha256sum -- "${FAILURE_RECORD_2}"
  fi
} | tee "${SHA256SUMS_PATH}"

echo "run_dir_1=${RUN_DIR_1}"
echo "run_dir_2=${RUN_DIR_2}"
echo "signature_v1=${SIG_1}"

