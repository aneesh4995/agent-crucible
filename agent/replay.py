"""Deterministic replay check for the guardrail.

The guardrail is meant to be a pure function: the same (policy, layers, profile,
tool, args, session taint state) must always yield the same verdict. This script
verifies that on RECORDED data. It takes the tool-call sequences the harness wrote
to its per-trial records (``out/trial-*.json``), feeds every call back through the
guardrail with the same policy, profile and layers, and reports whether each
verdict matches the one recorded during the live trial.

No model call and no infrastructure is involved: the harness records, before every
guardrail decision, exactly the session state the guardrail reads (``tainted`` and
``tainted_keys``), so a decision can be re-evaluated in isolation.

What is compared, per call:
  verdict   allow vs deny (the primary result)
  reason    the exact denial reason string ("" for allow)

What is NOT replayed: undefended trials (no verdict was recorded), the model's
behaviour, tool execution, or human-override decisions. For a call the guardrail
denied and a simulated operator then approved, the recorded verdict is the
guardrail's own (deny); the override is a separate event and is not re-run.

A mismatch means the live decision cannot be reproduced from its recorded inputs.
The usual cause is that ``guardrails/policy.yaml`` (or the guardrail code) changed
since the trial; the report states when the policy file hash differs from the one
recorded with the trial so that cause is visible rather than guessed.

Usage:
    python agent/replay.py out/trial-*.json
    python agent/replay.py out/results-<ts>.csv          # uses its trial_record column
    python agent/replay.py out/ --policy guardrails/policy.yaml --json

Exit status: 0 all verdicts match, 1 at least one mismatch, 2 nothing to replay.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import pathlib
import sys
from dataclasses import dataclass, field

HERE = pathlib.Path(__file__).parent
REPO = HERE.parent
for _p in (str(HERE), str(REPO / "guardrails")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from guardrail import POLICY_PATH, Guardrail  # noqa: E402
from tools import Session  # noqa: E402


@dataclass
class ReplayReport:
    records_total: int = 0
    records_replayed: int = 0          # records that had recorded verdicts
    records_skipped: list = field(default_factory=list)   # (file, reason)
    calls_checked: int = 0
    verdict_matches: int = 0
    reason_matches: int = 0
    unreplayable_calls: list = field(default_factory=list)  # call has verdict but no snapshot
    mismatches: list = field(default_factory=list)
    policy_changed_records: list = field(default_factory=list)

    @property
    def verdict_match_rate(self) -> float | None:
        return self.verdict_matches / self.calls_checked if self.calls_checked else None

    @property
    def reason_match_rate(self) -> float | None:
        return self.reason_matches / self.calls_checked if self.calls_checked else None


def _sha256_file(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_records(paths: list[pathlib.Path]) -> list[tuple[str, dict]]:
    """Resolve paths (trial JSONs, results CSVs, or directories) to (name, record)."""
    files: list[pathlib.Path] = []
    for p in paths:
        if p.is_dir():
            files += sorted(p.glob("trial-*.json"))
        elif p.suffix == ".csv":
            base = p.parent
            with p.open() as f:
                for row in csv.DictReader(f):
                    tr = row.get("trial_record")
                    if tr:
                        files.append(base / tr)
        else:
            files.append(p)
    out = []
    for f in files:
        try:
            out.append((f.name, json.loads(f.read_text())))
        except (OSError, json.JSONDecodeError) as e:
            out.append((f.name, {"_load_error": str(e)}))
    return out


def replay_records(records: list[tuple[str, dict]],
                   policy_path: pathlib.Path | None = None) -> ReplayReport:
    """Replay every recorded guardrail verdict. Pure: reads only its arguments."""
    policy_path = policy_path or POLICY_PATH
    current_policy_sha = _sha256_file(policy_path)
    rep = ReplayReport(records_total=len(records))
    for name, rec in records:
        if "_load_error" in rec:
            rep.records_skipped.append((name, f"unreadable: {rec['_load_error']}"))
            continue
        g = rec.get("guardrail") or {}
        if not g.get("enabled"):
            rep.records_skipped.append((name, "undefended (no recorded verdicts)"))
            continue
        rep.records_replayed += 1
        if g.get("policy_sha256") and g["policy_sha256"] != current_policy_sha:
            rep.policy_changed_records.append(name)
        guardrail = Guardrail(profile=g["profile"], layers=set(g["layers"]),
                              policy_path=policy_path)
        for call in rec.get("tool_calls", []):
            rec_v = call.get("guardrail")
            if rec_v is None:
                continue  # no verdict recorded for this call
            snap = rec_v.get("taint_before")
            if snap is None:
                rep.unreplayable_calls.append((name, call.get("seq"), call.get("tool")))
                continue
            session = Session(tainted=list(snap["tainted"]),
                              tainted_keys=set(snap["tainted_keys"]))
            allow, reason = guardrail.check(call["tool"], call.get("args", {}), session)
            rep.calls_checked += 1
            verdict_ok = allow == rec_v["allow"]
            reason_ok = reason == rec_v["reason"]
            rep.verdict_matches += verdict_ok
            rep.reason_matches += reason_ok
            if not (verdict_ok and reason_ok):
                a = json.dumps(call.get("args", {}), sort_keys=True)
                rep.mismatches.append({
                    "record": name, "seq": call.get("seq"), "tool": call["tool"],
                    "args": a if len(a) <= 160 else a[:160] + "…",
                    "recorded": {"allow": rec_v["allow"], "reason": rec_v["reason"]},
                    "replayed": {"allow": allow, "reason": reason},
                    "verdict_differs": not verdict_ok,
                })
    return rep


def format_report(rep: ReplayReport) -> str:
    lines = [f"records: {rep.records_total} total, {rep.records_replayed} with recorded "
             f"verdicts, {len(rep.records_skipped)} skipped"]
    for name, why in rep.records_skipped[:10]:
        lines.append(f"  skipped {name}: {why}")
    if len(rep.records_skipped) > 10:
        lines.append(f"  ... and {len(rep.records_skipped) - 10} more skipped")
    if rep.policy_changed_records:
        lines.append(f"WARNING: policy file differs from the one recorded in "
                     f"{len(rep.policy_changed_records)} record(s); mismatches below may "
                     f"be policy drift, not nondeterminism.")
    if rep.unreplayable_calls:
        lines.append(f"WARNING: {len(rep.unreplayable_calls)} call(s) had a verdict but no "
                     f"taint snapshot and could not be replayed.")
    if rep.calls_checked:
        lines.append(f"verdict match: {rep.verdict_matches}/{rep.calls_checked} "
                     f"({rep.verdict_match_rate:.1%})")
        lines.append(f"reason match:  {rep.reason_matches}/{rep.calls_checked} "
                     f"({rep.reason_match_rate:.1%})")
    else:
        lines.append("no guardrail verdicts found to replay")
    if rep.mismatches:
        lines.append(f"MISMATCHES ({len(rep.mismatches)}):")
        for m in rep.mismatches:
            kind = "VERDICT" if m["verdict_differs"] else "reason"
            lines.append(f"  [{kind}] {m['record']} call#{m['seq']} {m['tool']} {m['args']}\n"
                         f"      recorded: {m['recorded']}\n      replayed: {m['replayed']}")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description="Replay recorded guardrail verdicts (no model call).")
    ap.add_argument("paths", nargs="+", type=pathlib.Path,
                    help="trial-*.json files, a results-*.csv, or a directory of trial records")
    ap.add_argument("--policy", type=pathlib.Path, default=None,
                    help="policy file to replay against (default: guardrails/policy.yaml)")
    ap.add_argument("--json", action="store_true", help="print the report as JSON")
    args = ap.parse_args()

    records = load_records(args.paths)
    rep = replay_records(records, args.policy)
    if args.json:
        print(json.dumps({
            "records_total": rep.records_total, "records_replayed": rep.records_replayed,
            "calls_checked": rep.calls_checked, "verdict_matches": rep.verdict_matches,
            "reason_matches": rep.reason_matches,
            "verdict_match_rate": rep.verdict_match_rate,
            "policy_changed_records": rep.policy_changed_records,
            "unreplayable_calls": rep.unreplayable_calls,
            "mismatches": rep.mismatches}, indent=2))
    else:
        print(format_report(rep))
    if rep.calls_checked == 0:
        return 2
    return 0 if not rep.mismatches else 1


if __name__ == "__main__":
    sys.exit(main())
