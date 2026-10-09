"""Pull classifier-labeled trials into one readable file for hand-labeling.

The refusal classifier (refusal_classifier.is_refusal) is a deterministic
pattern match. Before its output is trusted for reported numbers, a human must
label a sample to measure its precision and recall. This script assembles that
sample: for a given results CSV it collects every trial the classifier flagged
as a refusal (held-refused / refused-then-*) PLUS a sample of held-unengaged
trials (to catch false negatives — real refusals the patterns missed), and
writes each with the model's final assistant text, the classifier verdict, and
the matched reason, in one JSON file.

It does NOT compute precision/recall — that is the human labeler's job after
filling in a "human_label" field.

Usage:
    python dump_refusal_sample.py out/results-<ts>.csv [--unengaged-sample N]
"""
from __future__ import annotations

import argparse
import csv
import json
import pathlib

HERE = pathlib.Path(__file__).parent
OUT = HERE / "out"


def _final_assistant_text(transcript: list) -> str:
    last = None
    for m in transcript:
        if isinstance(m, dict) and m.get("role") == "assistant":
            last = m
    if last is None:
        return "(no assistant message)"
    c = last.get("content")
    if isinstance(c, list):
        return " ".join(p.get("text", "") if isinstance(p, dict) else str(p) for p in c)
    return c or "(empty)"


def _transcript_path(stamp_csv: pathlib.Path, model: str, scenario: str, trial: str,
                     trial_record: str | None = None) -> pathlib.Path:
    # Preferred: the structured trial record names its transcript exactly (needed when
    # several conditions share one run, which adds a suffix to the file name).
    if trial_record:
        try:
            rec = json.loads((OUT / trial_record).read_text())
            return OUT / rec["transcript_file"]
        except (OSError, KeyError, json.JSONDecodeError):
            pass
    # Fallback for older results files: results-<stamp>.csv ->
    # transcript-<stamp>-<slug(model)>-<scenario>-t<trial>.json
    stamp = stamp_csv.stem.replace("results-", "")
    slug = model.replace("/", "_").replace(":", "_")
    return OUT / f"transcript-{stamp}-{slug}-{scenario}-t{trial}.json"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("results_csv", help="path to an out/results-<ts>.csv from a refusal run")
    ap.add_argument("--unengaged-sample", type=int, default=15,
                     help="how many held-unengaged trials to include for false-negative checking")
    args = ap.parse_args()

    csv_path = pathlib.Path(args.results_csv)
    rows = list(csv.DictReader(csv_path.open()))

    refusals, unengaged = [], []
    for r in rows:
        label = r.get("refusal_outcome", "")
        if label in ("held-refused", "refused-then-held", "refused-then-compromised"):
            refusals.append(r)
        elif label == "held-unengaged":
            unengaged.append(r)

    picked = refusals + unengaged[: args.unengaged_sample]
    sample = []
    for r in picked:
        tpath = _transcript_path(csv_path, r["model"], r["scenario"], r["trial"],
                                r.get("trial_record"))
        try:
            transcript = json.loads(tpath.read_text())
            final_text = _final_assistant_text(transcript)
        except Exception as e:  # noqa: BLE001 - want the reason inline for the labeler
            final_text = f"(could not read transcript {tpath.name}: {e})"
        sample.append({
            "model": r["model"],
            "scenario": r["scenario"],
            "trial": r["trial"],
            "classifier_verdict": r["refusal_outcome"],
            "refusal_detected": r.get("refusal_detected"),
            "pressure_injected": r.get("pressure_injected"),
            "compromised": r.get("compromised"),
            "final_assistant_text": final_text,
            "transcript_file": tpath.name,
            "human_label": "",   # <- fill in: "refusal" / "unengaged" / "other"
        })

    out_path = OUT / "refusal-classifier-sample.json"
    out_path.write_text(json.dumps(sample, indent=2))
    print(f"wrote {len(sample)} trials "
          f"({len(refusals)} classifier-positive, "
          f"{min(len(unengaged), args.unengaged_sample)} held-unengaged) -> {out_path}")
    print("Fill in each entry's 'human_label' to compute precision/recall.")


if __name__ == "__main__":
    main()
