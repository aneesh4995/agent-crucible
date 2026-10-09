"""Percent agreement and Cohen's kappa: human labels vs the harness's automated score.

Inputs:
  the label sheet the labeler filled in (human_label column), and
  the sample key written by draw_label_sample.py (sample_id -> automated label).

Method (two raters: the automated scorer and the human):
  * Only trials with a definite human label enter the agreement statistics. Rows
    labeled "unclear" or left blank are counted and reported but excluded, and the
    exclusion count is always printed so it cannot hide.
  * percent agreement = matching labels / labeled trials, with a 95% Wilson interval.
  * Cohen's kappa = (po - pe) / (1 - pe), po the observed agreement, pe the agreement
    expected by chance from each rater's marginal label frequencies. Kappa is
    undefined (reported as n/a) when pe == 1, i.e. only one label occurs.
  * The kappa interval is the usual large-sample normal approximation
    kappa +/- 1.96 * sqrt(po(1-po) / (n(1-pe)^2)); with small n or extreme marginals
    treat it as indicative only.
  * Agreement is also reported per scenario kind (attack / benign) and per scenario,
    with every disagreement listed.

Usage:
    python pilot/score_agreement.py label_sheet-<stem>.filled.csv sample_key-<stem>.csv [--json]
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import pathlib
import sys
from collections import Counter

ATTACK_LABELS = ("compromised", "held", "unclear")
BENIGN_LABELS = ("completed", "not_completed", "unclear")


def wilson(hits: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 0.0)
    p = hits / n
    denom = 1 + z * z / n
    center = p + z * z / (2 * n)
    spread = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (max(0.0, (center - spread) / denom), min(1.0, (center + spread) / denom))


def cohens_kappa(a: list[str], b: list[str]) -> dict:
    """Cohen's kappa for two equal-length label lists. kappa is None if undefined."""
    if len(a) != len(b):
        raise ValueError("label lists differ in length")
    n = len(a)
    if n == 0:
        return {"n": 0, "po": None, "pe": None, "kappa": None, "ci95": None}
    po = sum(x == y for x, y in zip(a, b)) / n
    ca, cb = Counter(a), Counter(b)
    pe = sum((ca[k] / n) * (cb[k] / n) for k in set(ca) | set(cb))
    if pe >= 1.0:
        return {"n": n, "po": po, "pe": pe, "kappa": None, "ci95": None}
    kappa = (po - pe) / (1 - pe)
    se = math.sqrt(po * (1 - po) / (n * (1 - pe) ** 2))
    return {"n": n, "po": po, "pe": pe, "kappa": kappa,
            "ci95": (kappa - 1.96 * se, kappa + 1.96 * se)}


def _read_csv(path: pathlib.Path) -> list[dict]:
    lines = [l for l in path.read_text().splitlines() if not l.startswith("#")]
    return list(csv.DictReader(lines))


def score(sheet_rows: list[dict], key_rows: list[dict]) -> dict:
    key = {r["sample_id"]: r for r in key_rows}
    problems, items, unclear, unlabeled = [], [], [], []
    for r in sheet_rows:
        sid = r["sample_id"]
        if sid not in key:
            problems.append(f"{sid}: not in the sample key")
            continue
        kind = r.get("scenario_kind", "attack")
        allowed = BENIGN_LABELS if kind == "benign" else ATTACK_LABELS
        human = (r.get("human_label") or "").strip().lower()
        if not human:
            unlabeled.append(sid)
            continue
        if human not in allowed:
            problems.append(f"{sid}: label '{human}' not valid for a {kind} scenario "
                            f"(use one of {', '.join(allowed)})")
            continue
        if human == "unclear":
            unclear.append(sid)
            continue
        items.append({"sample_id": sid, "scenario": r["scenario"], "kind": kind,
                      "human": human, "auto": key[sid]["automated_label"]})
    missing = sorted(set(key) - {r["sample_id"] for r in sheet_rows})
    for sid in missing:
        problems.append(f"{sid}: in the key but missing from the label sheet")

    def stats(sub: list[dict]) -> dict:
        hits = sum(i["human"] == i["auto"] for i in sub)
        lo, hi = wilson(hits, len(sub))
        k = cohens_kappa([i["auto"] for i in sub], [i["human"] for i in sub])
        return {"n": len(sub), "agree": hits,
                "percent_agreement": (hits / len(sub)) if sub else None,
                "agreement_ci95": (lo, hi), "kappa": k["kappa"],
                "kappa_ci95": k["ci95"], "po": k["po"], "pe": k["pe"]}

    by_kind = {k: stats([i for i in items if i["kind"] == k])
               for k in ("attack", "benign") if any(i["kind"] == k for i in items)}
    by_scn = {s: stats([i for i in items if i["scenario"] == s])
              for s in sorted({i["scenario"] for i in items})}
    confusion = Counter((i["auto"], i["human"]) for i in items)
    return {"overall": stats(items), "by_kind": by_kind, "by_scenario": by_scn,
            "labeled": len(items), "unclear": len(unclear), "unlabeled": len(unlabeled),
            "confusion": {f"auto={a} human={h}": c for (a, h), c in sorted(confusion.items())},
            "disagreements": [i for i in items if i["human"] != i["auto"]],
            "problems": problems}


def _fmt(s: dict) -> str:
    if not s["n"]:
        return "n=0"
    lo, hi = s["agreement_ci95"]
    k = "n/a (undefined)" if s["kappa"] is None else f"{s['kappa']:.3f}"
    kci = ("" if s["kappa_ci95"] is None
           else f" (~95% CI {s['kappa_ci95'][0]:.3f} to {s['kappa_ci95'][1]:.3f})")
    return (f"n={s['n']}  agreement {s['agree']}/{s['n']} = {s['percent_agreement']:.1%} "
            f"(95% Wilson {lo:.1%}-{hi:.1%})  kappa {k}{kci}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("label_sheet", type=pathlib.Path, help="the filled-in label sheet")
    ap.add_argument("sample_key", type=pathlib.Path)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    res = score(_read_csv(args.label_sheet), _read_csv(args.sample_key))
    if args.json:
        print(json.dumps(res, indent=2, default=list))
        return 1 if res["problems"] else 0
    print(f"labeled {res['labeled']} | excluded: {res['unclear']} unclear, "
          f"{res['unlabeled']} blank")
    print(f"OVERALL   {_fmt(res['overall'])}")
    for k, s in res["by_kind"].items():
        print(f"  {k:7s} {_fmt(s)}")
    for sc, s in res["by_scenario"].items():
        print(f"    {sc:30s} {_fmt(s)}")
    print("confusion (rows: automated, cols: human):")
    for k, c in res["confusion"].items():
        print(f"  {k}: {c}")
    if res["disagreements"]:
        print(f"disagreements ({len(res['disagreements'])}):")
        for d in res["disagreements"]:
            print(f"  {d['sample_id']} {d['scenario']}: automated={d['auto']} human={d['human']}")
    for p in res["problems"]:
        print(f"PROBLEM: {p}", file=sys.stderr)
    return 1 if res["problems"] else 0


if __name__ == "__main__":
    sys.exit(main())
