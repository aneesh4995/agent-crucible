"""Pilot instrumentation metrics, computed from a results CSV and its trial records.

These are the analyses that test whether the harness measures what it claims to,
NOT security outcomes: this script deliberately computes no attack success rate.
(Scoring validity - agreement and kappa against human labels - is
draw_label_sample.py / score_agreement.py.) Definitions match docs/pilot-protocol.md.

  fingerprint match rate   trials whose seed fingerprint equalled the reference /
                           trials that were checked. "unchecked" trials are
                           reported separately and excluded from the denominator.
  replay match rate        guardrail verdicts reproduced by agent/replay.py from the
                           recorded taint snapshots / verdicts checked.
  log completeness         a trial is complete iff all of:
                             1. its trial record exists and parses;
                             2. the record carries a 64-hex seed fingerprint, a
                                condition, and the three input hashes;
                             3. its transcript file exists and parses as a message list;
                             4. the number of tool calls in the record equals the number
                                of tool calls the assistant made in the transcript;
                             5. if the guardrail was enabled, every recorded tool call
                                has a verdict WITH a taint snapshot, and the record
                                names its policy hash.
                           Also reported: observed trials vs the expected count when a
                           pilot config is given (so missing rows are visible).
  benign task completion   per benign scenario and condition: utility-ok / trials,
                           with a 95% Wilson interval; errored trials are counted
                           in the denominator and shown separately.
  latency                  guardrail decision time (ms per call), and per condition
                           the trial wall-clock, model-call latency and tool-execution
                           time (median / p95 / max). Guardrail decision time is the
                           direct overhead; wall-clock differences between conditions
                           are confounded by model/provider variance and by different
                           trajectories (a denial changes what the model does next).

Usage:
    python pilot/pilot_metrics.py agent/out/results-<ts>.csv [--pilot-config pilot/pilot_config.yaml] [--json]
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import pathlib
import re
import statistics
import sys
from collections import defaultdict

REPO = pathlib.Path(__file__).resolve().parents[1]
for _p in (REPO / "agent", REPO / "guardrails"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import replay  # noqa: E402

HEX64 = re.compile(r"[0-9a-f]{64}")


def wilson(hits: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 0.0)
    p = hits / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    s = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (max(0.0, (c - s) / d), min(1.0, (c + s) / d))


def pct(sorted_vals: list[float], q: float) -> float:
    """Nearest-rank percentile of an already-sorted list."""
    return sorted_vals[max(0, math.ceil(q * len(sorted_vals)) - 1)]


def summarize(vals: list[float]) -> dict | None:
    if not vals:
        return None
    v = sorted(vals)
    return {"n": len(v), "median": statistics.median(v), "p95": pct(v, 0.95), "max": v[-1]}


def _load(path: pathlib.Path):
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def completeness(row: dict, results_dir: pathlib.Path) -> tuple[bool, str, dict | None]:
    """(complete?, first reason it is not, the parsed record or None)."""
    rec = _load(results_dir / row.get("trial_record", "")) if row.get("trial_record") else None
    if not isinstance(rec, dict):
        return False, "trial record missing or unreadable", None
    if not HEX64.fullmatch(rec.get("seed_fingerprint") or ""):
        return False, "no valid seed fingerprint", rec
    if not rec.get("condition") or set(rec.get("inputs") or {}) != {
            "scenario_sha256", "system_prompt_sha256", "tool_schema_sha256"}:
        return False, "condition or input hashes missing", rec
    transcript = _load(results_dir / rec.get("transcript_file", ""))
    if not isinstance(transcript, list):
        return False, "transcript missing or unreadable", rec
    n_tr = sum(len(m.get("tool_calls") or []) for m in transcript
               if isinstance(m, dict) and m.get("role") == "assistant")
    if n_tr != len(rec.get("tool_calls", [])):
        return False, f"tool-call count differs (transcript {n_tr}, record {len(rec.get('tool_calls', []))})", rec
    g = rec.get("guardrail") or {}
    if g.get("enabled"):
        if not g.get("policy_sha256"):
            return False, "guardrail record lacks policy hash", rec
        for c in rec["tool_calls"]:
            v = c.get("guardrail")
            if not v or "allow" not in v or v.get("taint_before") is None:
                return False, f"call #{c.get('seq')} lacks a verdict or taint snapshot", rec
    return True, "", rec


def compute(results_csv: pathlib.Path, benign_ids: set[str],
            expected_trials: int | None = None) -> dict:
    results_dir = results_csv.parent
    rows = list(csv.DictReader(results_csv.open()))
    out: dict = {"trials": len(rows)}

    # fingerprint
    fm = [r["fingerprint_match"] for r in rows]
    checked = [x for x in fm if x != "unchecked"]
    out["fingerprint"] = {
        "checked": len(checked), "unchecked": len(fm) - len(checked),
        "match": checked.count("match"), "mismatch": checked.count("MISMATCH"),
        "no_reference": checked.count("no-reference"),
        "match_rate": (checked.count("match") / len(checked)) if checked else None}

    # completeness + collect records
    incomplete, records = [], []
    for r in rows:
        ok, why, rec = completeness(r, results_dir)
        if rec is not None:
            records.append((r["trial_record"], rec))
        if not ok:
            incomplete.append({"scenario": r["scenario"], "trial": r["trial"],
                               "condition": r.get("condition"), "reason": why})
    comp = {"complete": len(rows) - len(incomplete), "of": len(rows),
            "rate": ((len(rows) - len(incomplete)) / len(rows)) if rows else None,
            "incomplete": incomplete}
    if expected_trials is not None:
        comp["expected_trials"] = expected_trials
        comp["missing_trials"] = max(0, expected_trials - len(rows))
    out["log_completeness"] = comp

    # replay
    rep = replay.replay_records(records)
    out["replay"] = {"calls_checked": rep.calls_checked, "verdict_matches": rep.verdict_matches,
                     "verdict_match_rate": rep.verdict_match_rate,
                     "reason_match_rate": rep.reason_match_rate,
                     "mismatches": rep.mismatches,
                     "policy_changed_records": rep.policy_changed_records,
                     "unreplayable_calls": rep.unreplayable_calls}

    # benign completion
    cells = defaultdict(lambda: [0, 0, 0])      # [ok, total, errors]
    for r in rows:
        if r["scenario"] in benign_ids:
            c = cells[(r["scenario"], r["condition"])]
            c[1] += 1
            c[0] += r["outcome"] == "utility-ok"
            c[2] += r["outcome"] == "error"
    out["benign_completion"] = {
        f"{s} | {cond}": {"completed": ok, "trials": n, "errors": e,
                          "rate": (ok / n) if n else None,
                          "ci95": wilson(ok, n)}
        for (s, cond), (ok, n, e) in sorted(cells.items())}

    # latency
    g_ms = [c["guardrail"]["ms"] for _, rec in records for c in rec["tool_calls"] if c.get("guardrail")]
    per_cond = defaultdict(lambda: {"trial_s": [], "llm_ms": [], "tool_ms": []})
    for r in rows:
        per_cond[r["condition"]]["trial_s"].append(float(r["duration_s"]))
    for _, rec in records:
        d = per_cond[rec["condition"]]
        d["llm_ms"] += rec.get("llm_latencies_ms", [])
        d["tool_ms"] += [c["tool_ms"] for c in rec["tool_calls"] if c.get("tool_ms") is not None]
    out["latency"] = {"guardrail_decision_ms": summarize(g_ms),
                      "by_condition": {k: {m: summarize(v) for m, v in d.items()}
                                       for k, d in sorted(per_cond.items())}}
    return out


def _f(x):
    return "n/a" if x is None else f"{x:.1%}"


def render(m: dict) -> str:
    fp, lc, rp = m["fingerprint"], m["log_completeness"], m["replay"]
    L = [f"trials: {m['trials']}"]
    L.append(f"fingerprint: {fp['match']}/{fp['checked']} match ({_f(fp['match_rate'])}); "
             f"{fp['mismatch']} mismatch, {fp['no_reference']} no-reference, "
             f"{fp['unchecked']} unchecked")
    L.append(f"replay: {rp['verdict_matches']}/{rp['calls_checked']} guardrail verdicts "
             f"reproduced ({_f(rp['verdict_match_rate'])}); reasons {_f(rp['reason_match_rate'])}; "
             f"{len(rp['mismatches'])} mismatch(es)")
    if rp["policy_changed_records"]:
        L.append(f"  WARNING: policy file differs from recorded in {len(rp['policy_changed_records'])} record(s)")
    exp = (f" (expected {lc['expected_trials']}, missing {lc['missing_trials']})"
           if "expected_trials" in lc else "")
    L.append(f"log completeness: {lc['complete']}/{lc['of']} ({_f(lc['rate'])}){exp}")
    for i in lc["incomplete"][:10]:
        L.append(f"  incomplete: {i['scenario']} t{i['trial']} [{i['condition']}]: {i['reason']}")
    L.append("benign task completion:")
    for k, v in m["benign_completion"].items():
        lo, hi = v["ci95"]
        L.append(f"  {k}: {v['completed']}/{v['trials']} ({_f(v['rate'])}, "
                 f"95% Wilson {lo:.1%}-{hi:.1%}), {v['errors']} errored")
    lat = m["latency"]
    g = lat["guardrail_decision_ms"]
    L.append("latency: guardrail decision " + ("n/a (no guardrail trials)" if not g else
             f"median {g['median']:.3f} ms, p95 {g['p95']:.3f} ms, max {g['max']:.3f} ms (n={g['n']})"))
    for cond, d in lat["by_condition"].items():
        parts = []
        for name, unit in (("trial_s", "s"), ("llm_ms", "ms"), ("tool_ms", "ms")):
            s = d[name]
            parts.append(f"{name} " + ("n/a" if not s else
                         f"median {s['median']:.2f}{unit} p95 {s['p95']:.2f}{unit}"))
        L.append(f"  {cond}: " + "; ".join(parts))
    return "\n".join(L)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("results_csv", type=pathlib.Path)
    ap.add_argument("--pilot-config", type=pathlib.Path,
                    help="to compute the expected trial count and flag missing trials")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    import yaml
    scenarios = yaml.safe_load((REPO / "agent" / "scenarios.yaml").read_text())["scenarios"]
    benign = {s["id"] for s in scenarios if s.get("benign")}
    expected = None
    if args.pilot_config:
        c = yaml.safe_load(args.pilot_config.read_text())
        expected = len(c["scenarios"]) * len(c["conditions"]) * int(c["trials_per_cell"])
    m = compute(args.results_csv, benign, expected)
    print(json.dumps(m, indent=2, default=list) if args.json else render(m))
    return 0


if __name__ == "__main__":
    sys.exit(main())
