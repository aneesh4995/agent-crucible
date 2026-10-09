"""Deterministic replay of recorded guardrail verdicts (no model, no infrastructure)."""
import copy
import csv
import json
import pathlib
import shutil

import pytest

import replay

FIX = pathlib.Path(__file__).parent / "fixtures"
POLICY = FIX / "policy_fixture.yaml"
RECORDS = FIX / "replay"


def load():
    return replay.load_records([RECORDS])


def test_replay_reproduces_every_verdict_on_the_fixture_log():
    rep = replay.replay_records(load(), POLICY)
    assert rep.records_total == 5
    assert rep.records_replayed == 4                      # the undefended record has no verdicts
    assert [n for n, _ in rep.records_skipped] == ["trial-e-undefended.json"]
    assert rep.calls_checked == 11
    assert rep.verdict_matches == 11 and rep.reason_matches == 11
    assert rep.verdict_match_rate == 1.0
    assert rep.mismatches == [] and rep.unreplayable_calls == []
    assert rep.policy_changed_records == []               # same policy hash as recorded


def test_fixture_covers_all_three_layers_and_both_verdicts():
    seen = set()
    for _, rec in load():
        for c in rec["tool_calls"]:
            v = c["guardrail"]
            if v:
                seen.add((v["reason"].split(":")[0] or "allow"))
    assert {"allow", "L1", "L2", "L3"} <= seen


def test_flipped_recorded_verdict_is_reported_as_a_mismatch():
    records = copy.deepcopy(load())
    name, rec = next(r for r in records if r[0] == "trial-a-triage-full.json")
    rec["tool_calls"][1]["guardrail"]["allow"] = True     # live run "allowed" a denied read
    rec["tool_calls"][1]["guardrail"]["reason"] = ""
    rep = replay.replay_records(records, POLICY)
    assert rep.verdict_matches == 10 and rep.calls_checked == 11
    assert len(rep.mismatches) == 1
    m = rep.mismatches[0]
    assert (m["record"], m["seq"], m["tool"]) == (name, 1, "read_s3")
    assert m["verdict_differs"] and m["recorded"]["allow"] and not m["replayed"]["allow"]


def test_reason_only_difference_is_distinguished_from_a_verdict_difference():
    records = copy.deepcopy(load())
    _, rec = next(r for r in records if r[0] == "trial-b-export-full.json")
    rec["tool_calls"][1]["guardrail"]["reason"] = "L2:some other wording"
    rep = replay.replay_records(records, POLICY)
    assert rep.verdict_matches == 11 and rep.reason_matches == 10
    assert len(rep.mismatches) == 1 and not rep.mismatches[0]["verdict_differs"]


def test_policy_drift_is_attributed_not_silent(tmp_path):
    drifted = tmp_path / "policy.yaml"
    drifted.write_text(POLICY.read_text().replace(
        'allowed_accounts:  ["000000000000", "self"]',
        'allowed_accounts:  ["000000000000", "self", "999888777666"]'))
    assert drifted.read_text() != POLICY.read_text()
    rep = replay.replay_records(load(), drifted)
    assert rep.mismatches, "the policy change must flip the external-account share verdict"
    assert rep.mismatches[0]["tool"] == "share_snapshot"
    assert "trial-d-l2-only.json" in rep.policy_changed_records
    assert "policy file differs" in replay.format_report(rep)


def test_call_without_taint_snapshot_is_unreplayable_not_assumed_clean():
    records = copy.deepcopy(load())
    _, rec = next(r for r in records if r[0] == "trial-c-l3-only.json")
    del rec["tool_calls"][1]["guardrail"]["taint_before"]
    rep = replay.replay_records(records, POLICY)
    assert rep.unreplayable_calls == [("trial-c-l3-only.json", 1, "http_post")]
    assert rep.calls_checked == 10


def test_load_records_accepts_a_results_csv(tmp_path):
    for f in RECORDS.glob("trial-*.json"):
        shutil.copy(f, tmp_path / f.name)
    results = tmp_path / "results-x.csv"
    with results.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["model", "trial_record"])
        w.writerow(["m", "trial-a-triage-full.json"])
        w.writerow(["m", "trial-c-l3-only.json"])
    names = [n for n, _ in replay.load_records([results])]
    assert names == ["trial-a-triage-full.json", "trial-c-l3-only.json"]


def test_cli_exit_codes(tmp_path, monkeypatch, capsys):
    def run(*argv):
        monkeypatch.setattr("sys.argv", ["replay.py", *map(str, argv)])
        return replay.main()

    assert run(RECORDS, "--policy", POLICY) == 0
    assert "verdict match: 11/11 (100.0%)" in capsys.readouterr().out

    bad = tmp_path / "trial-bad.json"
    rec = json.loads((RECORDS / "trial-a-triage-full.json").read_text())
    rec["tool_calls"][2]["guardrail"]["allow"] = True
    bad.write_text(json.dumps(rec))
    assert run(bad, "--policy", POLICY) == 1
    assert "MISMATCHES (1)" in capsys.readouterr().out

    assert run(RECORDS / "trial-e-undefended.json", "--policy", POLICY) == 2
    assert "no guardrail verdicts found to replay" in capsys.readouterr().out
