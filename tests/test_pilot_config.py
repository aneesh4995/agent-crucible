"""pilot/pilot_config.yaml and the --pilot-config runner flag."""
import json
import pathlib

import pytest
import yaml

import harness

REPO = pathlib.Path(__file__).resolve().parents[1]
CONFIG = REPO / "pilot" / "pilot_config.yaml"
FULL = {"L1", "L2", "L3"}


def cfg():
    return yaml.safe_load(CONFIG.read_text())


def scenarios():
    return harness.load_scenarios()


def test_shipped_config_lists_the_seven_pilot_scenarios_with_one_attack_per_channel():
    c = cfg()
    ids = [e["id"] for e in c["scenarios"]]
    assert ids == ["00-clean", "B1-log-cleanup", "B2-internal-export",
                   "01-blatant-override", "15-db-record-injection",
                   "07-confused-deputy-export", "M2-mcp-result-poison"]
    by_id = {s["id"]: s for s in scenarios()}
    assert all(i in by_id for i in ids)
    attacks = [e for e in c["scenarios"] if e["role"] == "attack"]
    assert [e["channel"] for e in attacks] == [
        "file", "database record", "attacker-controlled config", "MCP server output"]
    # roles agree with the corpus: B1/B2 are benign tasks, the four attacks are not
    assert by_id["B1-log-cleanup"].get("benign") and by_id["B2-internal-export"].get("benign")
    assert not any(by_id[e["id"]].get("benign") for e in attacks)
    # the channels really are what the config says
    assert by_id["M2-mcp-result-poison"].get("mcp_tool")
    assert "config/export-target.txt" in str(by_id["07-confused-deputy-export"]["runbooks"])
    assert by_id["15-db-record-injection"].get("db_tool")
    assert by_id["15-db-record-injection"].get("postgres_rows")


def test_shipped_config_settings():
    c = cfg()
    assert c["trials_per_cell"] == 30
    assert c["conditions"] == ["undefended", "full-guardrail"]
    assert c["model"] == "meta-llama/llama-3.1-8b-instruct"   # the frozen pilot model
    assert c["check_fingerprint"] is True
    assert c["fingerprint_reference"] == "fingerprints/reference.json"


def test_shipped_config_loads_with_its_model_set():
    loaded = harness.load_pilot_config(CONFIG, scenarios())
    assert loaded["model"] == "meta-llama/llama-3.1-8b-instruct"


def test_runner_refuses_while_model_is_todo(tmp_path):
    with pytest.raises(SystemExit) as e:
        harness.load_pilot_config(write_cfg(tmp_path, model="TODO"), scenarios())
    assert "TODO" in str(e.value)


def write_cfg(tmp_path, **over):
    c = cfg()
    c["model"] = "some-org/open-weight-model"
    c.update(over)
    p = tmp_path / "pilot.yaml"
    p.write_text(yaml.safe_dump(c, sort_keys=False))
    return p


def test_valid_config_normalises_for_the_runner(tmp_path):
    out = harness.load_pilot_config(write_cfg(tmp_path), scenarios())
    assert out["model"] == "some-org/open-weight-model"
    assert out["trials"] == 30 and out["max_steps"] == 8
    assert out["conditions"] == [None, FULL]         # undefended, full guardrail
    assert len(out["scenario_ids"]) == 7


@pytest.mark.parametrize("over,needle", [
    ({"scenarios": [{"id": "no-such-scenario"}]}, "unknown"),
    ({"trials_per_cell": 0}, "trials_per_cell"),
    ({"conditions": ["undefended", "bogus"]}, "conditions"),
    ({"model": ""}, "TODO"),
])
def test_invalid_config_is_rejected(tmp_path, over, needle):
    with pytest.raises(SystemExit) as e:
        harness.load_pilot_config(write_cfg(tmp_path, **over), scenarios())
    assert needle in str(e.value)


def run_main(monkeypatch, *argv):
    monkeypatch.setattr("sys.argv", ["harness.py", *map(str, argv)])
    harness.main()


def test_pilot_flag_excludes_experiment_flags(tmp_path, monkeypatch):
    p = write_cfg(tmp_path)
    for extra in (["--models", "x"], ["--scenarios", "00-clean"], ["--guardrail"],
                  ["--trials", "5"], ["--max-steps", "3"]):
        with pytest.raises(SystemExit) as e:
            run_main(monkeypatch, "--pilot-config", p, *extra)
        assert "do not also pass" in str(e.value) and extra[0] in str(e.value)


def test_pilot_run_passes_config_to_run_pairs_and_requires_the_reference(tmp_path, monkeypatch, capsys):
    p = write_cfg(tmp_path, fingerprint_reference=str(tmp_path / "ref.json"))
    # no reference file yet -> the runner stops with the instruction to generate it
    with pytest.raises(SystemExit) as e:
        run_main(monkeypatch, "--pilot-config", p)
    assert "--generate-fingerprint-reference" in str(e.value)

    (tmp_path / "ref.json").write_text(json.dumps(
        {"schema_version": 1, "scenarios": {}}))
    seen = {}

    def fake_run_pairs(pairs, trials, max_steps, layers, force_profile, custom_prompt,
                       endpoint, stamp, tag="", *a, **kw):
        seen.update(pairs=pairs, trials=trials, max_steps=max_steps, layers=layers, kw=kw)
        return tmp_path / "results.csv", []

    monkeypatch.setattr(harness, "run_pairs", fake_run_pairs)
    run_main(monkeypatch, "--pilot-config", p)
    assert [(m, s["id"]) for m, s in seen["pairs"]] == [
        ("some-org/open-weight-model", i) for i in cfg_ids()]
    assert seen["trials"] == 30 and seen["max_steps"] == 8
    assert seen["kw"]["conditions"] == [None, FULL]
    assert seen["kw"]["fingerprint_reference"] == {}     # reference was loaded and passed


def cfg_ids():
    return [e["id"] for e in cfg()["scenarios"]]


def test_pilot_runner_end_to_end_with_a_scripted_model(hermetic, tmp_path, monkeypatch, capsys):
    """The real runner path: config -> reference check -> interleaved conditions -> CSV -> summary."""
    import csv

    from conftest import attack_01_script

    ids = ["00-clean", "B1-log-cleanup", "01-blatant-override"]
    ref = tmp_path / "ref.json"
    harness.generate_fingerprint_reference([s for s in scenarios() if s["id"] in ids], ref)
    p = write_cfg(tmp_path, trials_per_cell=2, fingerprint_reference=str(ref),
                  scenarios=[{"id": i} for i in ids])
    hermetic.set_script(attack_01_script())
    run_main(monkeypatch, "--pilot-config", p)

    out = capsys.readouterr().out
    assert "[undefended]" in out and "[full-guardrail]" in out      # summary split by condition
    (results,) = list(hermetic.out.glob("results-*.csv"))
    rows = list(csv.DictReader(results.open()))
    assert len(rows) == 3 * 2 * 2                                    # scenarios x conditions x trials
    assert {r["fingerprint_match"] for r in rows} == {"match"}
    # interleaved: within a scenario, trial n runs undefended then guardrail before trial n+1
    first = [(r["trial"], r["condition"]) for r in rows if r["scenario"] == "00-clean"]
    assert first == [("1", "undefended"), ("1", "full-guardrail"),
                     ("2", "undefended"), ("2", "full-guardrail")]
    assert len(list(hermetic.out.glob("trial-*.json"))) == 12
