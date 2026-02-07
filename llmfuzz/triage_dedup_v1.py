from __future__ import annotations

import json
import os
from pathlib import Path

from .io import atomic_write_json, atomic_write_text


_SEVERITY_RANK: dict[str, int] = {
    "FAIL": 0,
    "TIMEOUT": 1,
    "BLOCKED": 2,
    "DRY_RUN": 3,
    "PASS": 4,
    "UNKNOWN": 5,
}


def _verdict_rank(verdict: str) -> int:
    if not verdict:
        return _SEVERITY_RANK["UNKNOWN"]
    return _SEVERITY_RANK.get(verdict, _SEVERITY_RANK["UNKNOWN"])


def _read_json_object(path: Path) -> dict | None:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    if not isinstance(raw, dict):
        return None
    return raw


def _get_spec_sha256(campaign_root: Path) -> str:
    summary_path = campaign_root / "summary.json"
    summary = _read_json_object(summary_path) if summary_path.exists() else None
    if isinstance(summary, dict):
        value = summary.get("spec_sha256")
        if isinstance(value, str):
            return value
    campaign_json_path = campaign_root / "campaign.json"
    campaign_json = (
        _read_json_object(campaign_json_path) if campaign_json_path.exists() else None
    )
    if isinstance(campaign_json, dict):
        value = campaign_json.get("spec_sha256")
        if isinstance(value, str):
            return value
    return ""


def _load_eval_fallback(campaign_root: Path, run_id: str) -> dict | None:
    if not run_id:
        return None
    path = campaign_root / "runs" / run_id / "llmfuzz" / "eval.json"
    if not path.exists():
        return None
    return _read_json_object(path)


def triage_campaign_v1(
    work_root_base: Path,
    campaign_id: str,
    *,
    top_k: int = 50,
    include_pass: bool = False,
    write_md: bool = True,
    patch_summary: bool = True,
) -> dict:
    work_root_base = Path(work_root_base)
    campaign_id = str(campaign_id)
    campaign_root = work_root_base / "llmfuzz" / "campaigns" / campaign_id
    cases_path = campaign_root / "cases.jsonl"
    triage_dir = campaign_root / "triage"
    triage_json_path = triage_dir / "triage.json"
    triage_md_path = triage_dir / "triage.md"

    os.makedirs(triage_dir, exist_ok=True)

    spec_sha256 = _get_spec_sha256(campaign_root)

    verdict_counts: dict[str, int] = {
        "PASS": 0,
        "FAIL": 0,
        "TIMEOUT": 0,
        "DRY_RUN": 0,
        "BLOCKED": 0,
        "UNKNOWN": 0,
    }

    clusters_map: dict[str, dict] = {}
    cases_total = 0

    if cases_path.exists():
        with open(cases_path, "r", encoding="utf-8") as handle:
            for line_index, raw_line in enumerate(handle):
                line = raw_line.strip()
                if not line:
                    continue
                cases_total += 1

                run_id = ""
                artifact_id = ""
                input_sha256 = ""
                case_index: int = int(line_index)
                signature_v1: str | None = None
                verdict_eval: str | None = None

                try:
                    obj = json.loads(line)
                except Exception:
                    obj = None

                if isinstance(obj, dict):
                    idx = obj.get("case_index")
                    if isinstance(idx, int) and not isinstance(idx, bool):
                        case_index = int(idx)

                    rid = obj.get("run_id")
                    if isinstance(rid, str):
                        run_id = rid

                    sig = obj.get("signature_v1")
                    if isinstance(sig, str) and sig:
                        signature_v1 = sig

                    ve = obj.get("verdict_eval")
                    if isinstance(ve, str) and ve:
                        verdict_eval = ve

                    aid = obj.get("artifact_id")
                    if isinstance(aid, str):
                        artifact_id = aid

                    ish = obj.get("input_sha256")
                    if isinstance(ish, str):
                        input_sha256 = ish

                if signature_v1 is None or verdict_eval is None:
                    ev = _load_eval_fallback(campaign_root, run_id)
                    if isinstance(ev, dict):
                        if verdict_eval is None:
                            v = ev.get("verdict_eval")
                            if not isinstance(v, str) or not v:
                                v = ev.get("verdict")
                            if isinstance(v, str) and v:
                                verdict_eval = v
                        if signature_v1 is None:
                            s = ev.get("signature_v1")
                            if isinstance(s, str) and s:
                                signature_v1 = s

                if not isinstance(verdict_eval, str) or not verdict_eval:
                    verdict_eval = "UNKNOWN"
                verdict_eval = verdict_eval.upper()
                if not isinstance(signature_v1, str) or not signature_v1:
                    signature_v1 = "UNKNOWN"

                verdict_counts.setdefault(verdict_eval, 0)
                verdict_counts[verdict_eval] += 1

                cluster_key = f"{verdict_eval}|{signature_v1}"
                cluster = clusters_map.get(cluster_key)
                if cluster is None:
                    cluster = {
                        "cluster_key": cluster_key,
                        "verdict_eval": verdict_eval,
                        "signature_v1": signature_v1,
                        "count": 0,
                        "first_case_index": case_index,
                        "first_run_id": run_id,
                        "representative": {
                            "case_index": case_index,
                            "run_id": run_id,
                            "artifact_id": artifact_id,
                            "input_sha256": input_sha256,
                        },
                        "sample_refs": [],
                    }
                    clusters_map[cluster_key] = cluster

                cluster["count"] += 1

                rep = cluster["representative"]
                rep_case_index = rep.get("case_index")
                rep_run_id = rep.get("run_id")
                if not isinstance(rep_case_index, int):
                    rep_case_index = case_index
                if not isinstance(rep_run_id, str):
                    rep_run_id = ""
                if (case_index, run_id) < (rep_case_index, rep_run_id):
                    cluster["first_case_index"] = case_index
                    cluster["first_run_id"] = run_id
                    cluster["representative"] = {
                        "case_index": case_index,
                        "run_id": run_id,
                        "artifact_id": artifact_id,
                        "input_sha256": input_sha256,
                    }

                refs = cluster["sample_refs"]
                refs.append({"case_index": case_index, "run_id": run_id})
                refs.sort(key=lambda r: (r["case_index"], r["run_id"]))
                if len(refs) > 5:
                    refs.pop()

    clusters_all = list(clusters_map.values())
    clusters_included = [
        c for c in clusters_all if include_pass or c.get("verdict_eval") != "PASS"
    ]

    clusters_included.sort(
        key=lambda c: (
            _verdict_rank(str(c.get("verdict_eval") or "")),
            -int(c.get("count") or 0),
            int(c.get("first_case_index") or 0),
            str(c.get("cluster_key") or ""),
        )
    )

    unique_sets: dict[str, set[str]] = {}
    for c in clusters_included:
        v = str(c.get("verdict_eval") or "UNKNOWN")
        s = str(c.get("signature_v1") or "UNKNOWN")
        unique_sets.setdefault(v, set()).add(s)

    unique_signatures_by_verdict = {k: len(unique_sets[k]) for k in sorted(unique_sets.keys())}
    unique_signatures_total = sum(unique_signatures_by_verdict.values())

    triage_obj = {
        "schema_version": "llmfuzz.triage.v1",
        "campaign_id": campaign_id,
        "spec_sha256": spec_sha256,
        "cases_total": int(cases_total),
        "verdict_counts": verdict_counts,
        "unique_signatures_total": int(unique_signatures_total),
        "unique_signatures_by_verdict": unique_signatures_by_verdict,
        "clusters": clusters_included,
    }

    atomic_write_json(str(triage_json_path), triage_obj)

    if write_md:
        limit = int(top_k) if int(top_k) >= 0 else 0
        top = clusters_included[:limit] if limit else []

        lines: list[str] = []
        lines.append(f"# Triage (Campaign Dedup v1)")
        lines.append("")
        lines.append(f"- campaign_id: `{campaign_id}`")
        lines.append(f"- cases_total: {cases_total}")
        lines.append(f"- unique_signatures_total: {unique_signatures_total}")
        lines.append("")
        lines.append("## Top clusters")
        lines.append("")
        lines.append("| rank | verdict | signature | count | first_case | representative_run |")
        lines.append("| ---: | :------ | :-------- | ----: | ---------: | :----------------- |")
        for i, c in enumerate(top, start=1):
            lines.append(
                f"| {i} | {c.get('verdict_eval','')} | {c.get('signature_v1','')} | {c.get('count',0)} | {c.get('first_case_index',0)} | {c.get('first_run_id','')} |"
            )
        lines.append("")
        lines.append("## Totals")
        lines.append("")
        lines.append(f"- cases_total: {cases_total}")
        lines.append(f"- verdict_counts: `{json.dumps(verdict_counts, sort_keys=True)}`")
        lines.append(
            f"- unique_signatures_by_verdict: `{json.dumps(unique_signatures_by_verdict, sort_keys=True)}`"
        )
        lines.append(f"- unique_signatures_total: {unique_signatures_total}")
        lines.append("")

        atomic_write_text(str(triage_md_path), "\n".join(lines) + "\n")

    if patch_summary:
        summary_path = campaign_root / "summary.json"
        if summary_path.exists():
            summary = _read_json_object(summary_path)
            if not isinstance(summary, dict):
                raise ValueError("summary.json is not a JSON object")
            summary["unique_signatures_total"] = unique_signatures_total
            summary["unique_signatures_by_verdict"] = unique_signatures_by_verdict
            limit = max(0, int(top_k))
            top_n = clusters_included[: min(limit, len(clusters_included))] if limit else []
            summary["top_clusters"] = []
            for c in top_n:
                rep_run_id = ""
                rep = c.get("representative")
                if isinstance(rep, dict) and isinstance(rep.get("run_id"), str):
                    rep_run_id = rep.get("run_id") or ""
                if not rep_run_id:
                    rep_run_id = str(c.get("first_run_id") or "")
                summary["top_clusters"].append(
                    {
                        "cluster_key": str(c.get("cluster_key") or ""),
                        "count": int(c.get("count") or 0),
                        "representative_run_id": rep_run_id,
                    }
                )
            atomic_write_json(str(summary_path), summary)

    return triage_obj

