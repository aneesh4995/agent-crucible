"""Draw a blind labeling sample from a harness results file.

Purpose: measure agreement between the harness's automated scoring and an
independent human reading of the same trials (PRQ1). The labeler must NOT see the
automated score, so this script writes two files:

  label_sheet-<stem>.csv   give this to the labeler. Columns: sample_id, scenario,
                           scenario_kind, condition, transcript, human_label, notes.
                           No automated outcome, flags, compromise indicator, or
                           trial/record identifier that could be looked up.
  sample_key-<stem>.csv    KEEP THIS AWAY from the labeler. sample_id -> the trial,
                           its trial record and the automated outcome/label.

Sampling:
  * frame   = every trial in the results file whose automated outcome is not
              "error" (an errored trial has no transcript to judge; the count of
              excluded error trials is printed).
  * strata  = (scenario, automated outcome).
  * size    = ceil(fraction * N) trials from each stratum, minimum 1, so the total
              is at least `fraction` of the frame and every non-empty stratum
              (including rare outcomes) is represented. Default fraction = 0.10.
  * order   = the sampled trials are shuffled with a seeded RNG BEFORE sample ids
              are assigned, so neither id order nor row order reveals a stratum.
  * seed    = recorded in the key file's header comment line via --seed (default 0)
              so the draw is reproducible.

Label vocabulary the labeler must use (judge from the transcript alone):
  attack scenarios   compromised | held | unclear
  benign scenarios   completed | not_completed | unclear
See docs/pilot-protocol.md for the codebook.

Usage:
    python pilot/draw_label_sample.py agent/out/results-<ts>.csv [--fraction 0.10]
                                      [--seed 0] [--out-dir DIR]
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import pathlib
import random
import sys
from collections import defaultdict

REPO = pathlib.Path(__file__).resolve().parents[1]

# automated outcome -> the label a human would use for the same judgment
AUTO_TO_LABEL = {
    "COMPROMISED": "compromised",
    "held": "held",
    "utility-ok": "completed",
    "utility-BLOCKED": "not_completed",
}
ATTACK_LABELS = ("compromised", "held", "unclear")
BENIGN_LABELS = ("completed", "not_completed", "unclear")


def render_transcript(messages: list[dict]) -> str:
    """A plain-text transcript: the operator prompt, tool calls, tool results, replies."""
    lines: list[str] = []
    for m in messages:
        role = m.get("role")
        if role == "system":
            continue  # identical for every trial
        if role == "user":
            lines.append(f"[operator] {m.get('content', '')}")
        elif role == "assistant":
            if m.get("content"):
                lines.append(f"[assistant] {m['content']}")
            for tc in m.get("tool_calls") or []:
                fn = tc.get("function", {})
                lines.append(f"[assistant -> tool] {fn.get('name')}({fn.get('arguments')})")
        elif role == "tool":
            lines.append(f"[tool result] {m.get('content', '')}")
        elif "error" in m:
            lines.append(f"[harness error] {m['error']}")
    return "\n".join(lines)


def draw_sample(rows: list[dict], fraction: float, seed: int) -> tuple[list[dict], dict]:
    """Stratified sample of result rows. Returns (sampled rows, summary)."""
    if not 0 < fraction <= 1:
        raise ValueError("fraction must be in (0, 1]")
    frame = [r for r in rows if r["outcome"] != "error"]
    strata: dict[tuple, list[dict]] = defaultdict(list)
    for r in frame:
        strata[(r["scenario"], r["outcome"])].append(r)
    rng = random.Random(seed)
    picked: list[dict] = []
    for key in sorted(strata):
        members = strata[key]
        n = max(1, math.ceil(fraction * len(members)))
        picked += rng.sample(members, min(n, len(members)))
    rng.shuffle(picked)  # BEFORE ids are assigned: order must not reveal the stratum
    summary = {"results_rows": len(rows), "frame": len(frame),
               "excluded_errors": len(rows) - len(frame), "sampled": len(picked),
               "sampled_fraction": (len(picked) / len(frame)) if frame else 0.0,
               "strata": len(strata), "seed": seed, "fraction": fraction}
    return picked, summary


def write_sheet_and_key(picked: list[dict], results_dir: pathlib.Path, benign_ids: set[str],
                        sheet_path: pathlib.Path, key_path: pathlib.Path,
                        seed: int) -> None:
    sheet_rows, key_rows = [], []
    for i, r in enumerate(picked, 1):
        sid = f"S{i:03d}"
        rec = json.loads((results_dir / r["trial_record"]).read_text())
        messages = json.loads((results_dir / rec["transcript_file"]).read_text())
        kind = "benign" if r["scenario"] in benign_ids else "attack"
        sheet_rows.append({
            "sample_id": sid, "scenario": r["scenario"], "scenario_kind": kind,
            "condition": r.get("condition", ""),
            "transcript": render_transcript(messages),
            "human_label": "", "notes": ""})
        key_rows.append({
            "sample_id": sid, "model": r["model"], "scenario": r["scenario"],
            "trial": r["trial"], "condition": r.get("condition", ""),
            "trial_record": r["trial_record"],
            "automated_outcome": r["outcome"],
            "automated_label": AUTO_TO_LABEL.get(r["outcome"], ""),
            "compromised": r["compromised"], "flags": r["flags"]})
    with sheet_path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["sample_id", "scenario", "scenario_kind",
                                          "condition", "transcript", "human_label", "notes"])
        w.writeheader()
        w.writerows(sheet_rows)
    with key_path.open("w", newline="") as f:
        f.write(f"# draw seed={seed}; DO NOT SHARE WITH THE LABELER\n")
        w = csv.DictWriter(f, fieldnames=list(key_rows[0]) if key_rows else ["sample_id"])
        w.writeheader()
        w.writerows(key_rows)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("results_csv", type=pathlib.Path)
    ap.add_argument("--fraction", type=float, default=0.10,
                    help="minimum fraction of trials to sample (default 0.10)")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--out-dir", type=pathlib.Path, default=None,
                    help="where to write the two files (default: next to the results file)")
    args = ap.parse_args()

    rows = list(csv.DictReader(args.results_csv.open()))
    if not rows or "trial_record" not in rows[0]:
        sys.exit(f"{args.results_csv}: no 'trial_record' column; this needs a results file "
                 f"written by the current harness.")
    sys.path.insert(0, str(REPO / "agent"))
    import yaml
    scenarios = yaml.safe_load((REPO / "agent" / "scenarios.yaml").read_text())["scenarios"]
    benign_ids = {s["id"] for s in scenarios if s.get("benign")}

    picked, summary = draw_sample(rows, args.fraction, args.seed)
    out_dir = args.out_dir or args.results_csv.parent
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = args.results_csv.stem.replace("results-", "")
    sheet, key = out_dir / f"label_sheet-{stem}.csv", out_dir / f"sample_key-{stem}.csv"
    write_sheet_and_key(picked, args.results_csv.parent, benign_ids, sheet, key, args.seed)

    print(f"frame: {summary['frame']} trials ({summary['excluded_errors']} errored trials "
          f"excluded); {summary['strata']} strata (scenario x outcome)")
    print(f"sampled: {summary['sampled']} ({summary['sampled_fraction']:.1%}; "
          f"minimum requested {summary['fraction']:.0%}), seed {summary['seed']}")
    print(f"label sheet (give to labeler): {sheet}")
    print(f"sample key  (keep away from labeler): {key}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
