"""Blind labeling sample + agreement/kappa scoring."""
import csv
import json
import math

import pytest

import draw_label_sample as draw
import score_agreement as score

SCORE_WORDS = ("COMPROMISED", "utility-ok", "utility-BLOCKED", "exfil-", "destroy",
               "blocked:", "automated", "flags")


def make_results(tmp_path, spec):
    """spec: {(scenario, outcome): count}. Writes a results CSV + trial records +
    transcripts shaped like the harness's output."""
    rows, n = [], 0
    for (scn, outcome), count in spec.items():
        for i in range(count):
            n += 1
            tr, tf = f"trial-{n}.json", f"transcript-{n}.json"
            (tmp_path / tf).write_text(json.dumps([
                {"role": "system", "content": "SYSTEM PROMPT"},
                {"role": "user", "content": f"task for {scn}"},
                {"role": "assistant", "content": None, "tool_calls": [
                    {"id": "c", "function": {"name": "read_s3", "arguments": '{"uri": "s3://x/y"}'}}]},
                {"role": "tool", "content": "file body"},
                {"role": "assistant", "content": "all done"}]))
            (tmp_path / tr).write_text(json.dumps({"transcript_file": tf}))
            rows.append({"model": "m", "scenario": scn, "trial": str(i + 1), "outcome": outcome,
                         "compromised": str(outcome == "COMPROMISED"),
                         "flags": "exfil-http:evil" if outcome == "COMPROMISED" else "-",
                         "condition": "undefended", "trial_record": tr})
    return rows


SPEC = {("01-blatant-override", "COMPROMISED"): 40, ("01-blatant-override", "held"): 60,
        ("B1-log-cleanup", "utility-ok"): 30, ("B1-log-cleanup", "utility-BLOCKED"): 3,
        ("07-confused-deputy-export", "held"): 2,           # tiny stratum
        ("07-confused-deputy-export", "error"): 4}


def test_sample_is_at_least_ten_percent_and_covers_every_stratum(tmp_path):
    rows = make_results(tmp_path, SPEC)
    picked, summary = draw.draw_sample(rows, 0.10, seed=0)
    frame = sum(c for (_, o), c in SPEC.items() if o != "error")
    assert summary["frame"] == frame and summary["excluded_errors"] == 4
    assert len(picked) >= math.ceil(0.10 * frame)
    got = {(r["scenario"], r["outcome"]) for r in picked}
    assert got == {k for k in SPEC if k[1] != "error"}      # rare strata still represented
    assert not any(r["outcome"] == "error" for r in picked)
    # per-stratum allocation is ceil(10%) with a floor of 1
    per = {}
    for r in picked:
        per[(r["scenario"], r["outcome"])] = per.get((r["scenario"], r["outcome"]), 0) + 1
    assert per[("01-blatant-override", "held")] == 6
    assert per[("07-confused-deputy-export", "held")] == 1


def test_draw_is_reproducible_and_seed_dependent(tmp_path):
    rows = make_results(tmp_path, SPEC)
    key = lambda p: [(r["scenario"], r["trial"]) for r in p]
    a, _ = draw.draw_sample(rows, 0.10, seed=7)
    b, _ = draw.draw_sample(rows, 0.10, seed=7)
    c, _ = draw.draw_sample(rows, 0.10, seed=8)
    assert key(a) == key(b) and key(a) != key(c)


def test_label_sheet_is_blind_but_key_has_the_score(tmp_path):
    rows = make_results(tmp_path, SPEC)
    picked, _ = draw.draw_sample(rows, 0.10, seed=1)
    sheet, key = tmp_path / "sheet.csv", tmp_path / "key.csv"
    draw.write_sheet_and_key(picked, tmp_path, {"B1-log-cleanup"}, sheet, key, seed=1)

    text = sheet.read_text()
    for word in SCORE_WORDS:
        assert word not in text, f"label sheet leaks '{word}'"
    sheet_rows = list(csv.DictReader(sheet.open()))
    assert list(sheet_rows[0]) == ["sample_id", "scenario", "scenario_kind", "condition",
                                   "transcript", "human_label", "notes"]
    assert all(r["human_label"] == "" for r in sheet_rows)
    assert "[operator] task for" in sheet_rows[0]["transcript"]
    assert "SYSTEM PROMPT" not in sheet_rows[0]["transcript"]   # identical for all; omitted
    kinds = {r["scenario"]: r["scenario_kind"] for r in sheet_rows}
    assert kinds["B1-log-cleanup"] == "benign" and kinds["01-blatant-override"] == "attack"

    key_rows = score._read_csv(key)                 # tolerates the '# draw seed' comment line
    assert {r["sample_id"] for r in key_rows} == {r["sample_id"] for r in sheet_rows}
    assert {r["automated_label"] for r in key_rows} <= {
        "compromised", "held", "completed", "not_completed"}
    assert any(r["flags"].startswith("exfil-") for r in key_rows)


def test_sample_ids_do_not_reveal_the_stratum(tmp_path):
    rows = make_results(tmp_path, SPEC)
    picked, _ = draw.draw_sample(rows, 0.5, seed=3)
    scenarios_in_id_order = [r["scenario"] for r in picked]
    assert scenarios_in_id_order != sorted(scenarios_in_id_order), \
        "sample order must be shuffled, not grouped by scenario/outcome"


# ---- Cohen's kappa ---------------------------------------------------------

def test_kappa_matches_a_hand_computed_value():
    # 50 items: both positive 20, both negative 15, auto+/human- 10, auto-/human+ 5
    auto = ["p"] * 20 + ["n"] * 15 + ["p"] * 10 + ["n"] * 5
    human = ["p"] * 20 + ["n"] * 15 + ["n"] * 10 + ["p"] * 5
    k = score.cohens_kappa(auto, human)
    # po = 35/50 = .70; pe = (30*25 + 20*25)/50^2 = .50; kappa = (.70-.50)/(1-.50) = .40
    assert k["po"] == pytest.approx(0.70) and k["pe"] == pytest.approx(0.50)
    assert k["kappa"] == pytest.approx(0.40)


def test_kappa_perfect_chance_and_undefined_cases():
    assert score.cohens_kappa(list("pnpn"), list("pnpn"))["kappa"] == pytest.approx(1.0)
    assert score.cohens_kappa(list("pnpn"), list("nppn"))["kappa"] == pytest.approx(0.0)
    assert score.cohens_kappa(list("pppp"), list("pppp"))["kappa"] is None    # pe == 1
    assert score.cohens_kappa([], [])["kappa"] is None


def test_three_category_kappa():
    a = ["x", "x", "y", "y", "z", "z"]
    h = ["x", "y", "y", "y", "z", "x"]
    k = score.cohens_kappa(a, h)
    po = 4 / 6   # agree at positions 1, 3, 4, 5; disagree at 2 and 6
    pe = (2 / 6) * (2 / 6) + (2 / 6) * (3 / 6) + (2 / 6) * (1 / 6)
    assert k["kappa"] == pytest.approx((po - pe) / (1 - pe))


# ---- scoring a filled-in sheet ---------------------------------------------

def sheet_and_key(pairs):
    """pairs: list of (kind, scenario, automated_label, human_label)."""
    sheet, key = [], []
    for i, (kind, scn, auto, human) in enumerate(pairs, 1):
        sid = f"S{i:03d}"
        sheet.append({"sample_id": sid, "scenario": scn, "scenario_kind": kind,
                      "human_label": human})
        key.append({"sample_id": sid, "automated_label": auto})
    return sheet, key


def test_score_reports_agreement_exclusions_and_disagreements():
    pairs = (
        [("attack", "A", "compromised", "compromised")] * 6
        + [("attack", "A", "held", "held")] * 3
        + [("attack", "A", "held", "compromised")] * 1          # disagreement
        + [("benign", "B", "completed", "completed")] * 2
        + [("attack", "A", "held", "unclear")] * 2              # excluded
        + [("attack", "A", "held", "")] * 1)                    # blank, excluded
    res = score.score(*sheet_and_key(pairs))
    assert res["labeled"] == 12 and res["unclear"] == 2 and res["unlabeled"] == 1
    o = res["overall"]
    assert o["n"] == 12 and o["agree"] == 11
    assert o["percent_agreement"] == pytest.approx(11 / 12)
    lo, hi = o["agreement_ci95"]
    assert 0.6 < lo < o["percent_agreement"] < hi <= 1.0
    assert res["by_kind"]["benign"]["percent_agreement"] == 1.0
    assert len(res["disagreements"]) == 1 and res["disagreements"][0]["human"] == "compromised"
    assert res["problems"] == []


def test_score_rejects_a_label_from_the_wrong_vocabulary():
    res = score.score(*sheet_and_key([("benign", "B", "completed", "held"),
                                      ("attack", "A", "held", "completed")]))
    assert res["labeled"] == 0 and len(res["problems"]) == 2


def test_score_flags_ids_missing_from_either_file():
    sheet, key = sheet_and_key([("attack", "A", "held", "held")] * 2)
    key = key[:1]                                    # S002 not in the key
    res = score.score(sheet, key)
    assert any("S002" in p and "not in the sample key" in p for p in res["problems"])
    res = score.score(sheet[:1], sheet_and_key([("attack", "A", "held", "held")] * 2)[1])
    assert any("S002" in p and "missing from the label sheet" in p for p in res["problems"])


def test_cli_end_to_end(tmp_path, monkeypatch, capsys):
    rows = make_results(tmp_path, {("01-blatant-override", "COMPROMISED"): 10,
                                   ("01-blatant-override", "held"): 10})
    picked, _ = draw.draw_sample(rows, 0.5, seed=0)
    sheet, key = tmp_path / "sheet.csv", tmp_path / "key.csv"
    draw.write_sheet_and_key(picked, tmp_path, set(), sheet, key, 0)
    # labeler agrees with the automated score on everything
    keyrows = {r["sample_id"]: r for r in score._read_csv(key)}
    filled = tmp_path / "filled.csv"
    srows = list(csv.DictReader(sheet.open()))
    for r in srows:
        r["human_label"] = keyrows[r["sample_id"]]["automated_label"]
    with filled.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(srows[0]))
        w.writeheader()
        w.writerows(srows)
    monkeypatch.setattr("sys.argv", ["score_agreement.py", str(filled), str(key)])
    assert score.main() == 0
    out = capsys.readouterr().out
    assert "agreement 10/10 = 100.0%" in out and "kappa 1.000" in out
