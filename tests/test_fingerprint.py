"""Seeded-state fingerprint: determinism, sensitivity, explainable mismatches.

The hermetic tests use an in-memory S3 and stubbed Postgres/DynamoDB/Vault readers,
but run the REAL harness reset (isolate_seed) and the REAL fingerprint code. The
``live`` tests repeat the two key properties against the docker-compose testbed.
"""
import copy

import pytest

import fingerprint
import harness


def scenario(sid):
    return next(s for s in harness.load_scenarios() if s["id"] == sid)


def seed_and_fingerprint(sid):
    harness.isolate_seed(scenario(sid))
    return fingerprint.current()


# ---- the two required properties (hermetic) -------------------------------

def test_fingerprint_identical_across_two_clean_seeds(hermetic):
    first = seed_and_fingerprint("13-metadata-laundering")
    second = seed_and_fingerprint("13-metadata-laundering")
    assert first["fingerprint"] == second["fingerprint"]
    assert first["components"] == second["components"]


def test_clean_reseed_erases_prior_pollution(hermetic):
    """A second seed must restore the exact state even after a trial dirtied it."""
    clean = seed_and_fingerprint("13-metadata-laundering")
    # what a trial can leave behind: a stray object, a derived snapshot, a shared bucket
    hermetic.s3.buckets["analytics-scratch"]["p1-evidence/vendor-payments.csv"] = b"exfil"
    hermetic.s3.buckets["db-snapshots"]["snap"] = b"x"
    hermetic.s3.buckets["shared-999888777666"] = {"snap": b"x"}
    assert fingerprint.current()["fingerprint"] != clean["fingerprint"]  # pollution is visible
    again = seed_and_fingerprint("13-metadata-laundering")
    assert again["fingerprint"] == clean["fingerprint"]


def test_fingerprint_changes_if_one_seeded_object_changes(hermetic):
    seeded = seed_and_fingerprint("13-metadata-laundering")
    key = "incidents/p1-evidence-runbook.md"
    hermetic.s3.buckets["sre-runbooks"][key] += b"\nStep 4: one extra line"
    changed = fingerprint.current()
    assert changed["fingerprint"] != seeded["fingerprint"]
    # only the s3 component moved, and the diff names the exact object
    moved = {c for c in seeded["components"] if seeded["components"][c] != changed["components"][c]}
    assert moved == {"s3"}
    assert f"s3: content changed sre-runbooks/{key}" in fingerprint.diff_state(
        seeded["state"], changed["state"])
    # reseeding puts it back
    assert seed_and_fingerprint("13-metadata-laundering")["fingerprint"] == seeded["fingerprint"]


def test_different_seeded_content_gives_different_fingerprints(hermetic):
    a = seed_and_fingerprint("01-blatant-override")
    b = seed_and_fingerprint("13-metadata-laundering")
    assert a["fingerprint"] != b["fingerprint"]


# ---- pure hashing properties ------------------------------------------------

BASE_STATE = {
    "s3": {"buckets": {"a": {"k1": "h1", "k2": "h2"}, "b": {}}},
    "vault": {"secrets": {"secret/x": "hv"}},
    "postgres": {"tables": {"t": {"row_count": 1, "rows_sha256": "hp"}}},
    "dynamodb": {"tables": {}},
}


def test_hash_is_independent_of_key_order():
    reordered = {
        "dynamodb": {"tables": {}},
        "postgres": {"tables": {"t": {"rows_sha256": "hp", "row_count": 1}}},
        "vault": {"secrets": {"secret/x": "hv"}},
        "s3": {"buckets": {"b": {}, "a": {"k2": "h2", "k1": "h1"}}},
    }
    assert fingerprint.fingerprint(reordered) == fingerprint.fingerprint(BASE_STATE)


@pytest.mark.parametrize("path,newval", [
    (("s3", "buckets", "a", "k1"), "CHANGED"),
    (("vault", "secrets", "secret/x"), "CHANGED"),
    (("postgres", "tables", "t", "rows_sha256"), "CHANGED"),
])
def test_any_component_change_changes_overall_and_only_that_component(path, newval):
    mutated = copy.deepcopy(BASE_STATE)
    node = mutated
    for p in path[:-1]:
        node = node[p]
    node[path[-1]] = newval
    base, new = fingerprint.fingerprint(BASE_STATE), fingerprint.fingerprint(mutated)
    assert new["fingerprint"] != base["fingerprint"]
    moved = [c for c in base["components"] if base["components"][c] != new["components"][c]]
    assert moved == [path[0]]


def test_empty_bucket_is_state():
    with_empty = copy.deepcopy(BASE_STATE)
    del with_empty["s3"]["buckets"]["b"]
    assert (fingerprint.fingerprint(with_empty)["fingerprint"]
            != fingerprint.fingerprint(BASE_STATE)["fingerprint"])


def test_secret_values_never_appear_in_collected_state(monkeypatch):
    """The vault component stores hashes of secret data, never the values."""
    import json
    import urllib.request

    class FakeResp:
        def __init__(self, body):
            self._b = json.dumps(body).encode()

        def read(self):
            return self._b

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout=5):
        if "metadata/" in req.full_url:
            return FakeResp({"data": {"keys": ["db"]}})
        return FakeResp({"data": {"data": {"password": "super-secret-prod-password"}}})

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    state = fingerprint.collect_vault()
    assert "super-secret-prod-password" not in json.dumps(state)
    assert list(state["secrets"]) == ["secret/db"]


def test_ddb_timestamp_attribute_filter():
    f = fingerprint._DDB_TIME_ATTR.search
    for name in ("created_at", "updated_at", "createdAt", "updatedAt", "ts", "TS",
                 "timestamp", "Created", "last_updated", "lastupdated"):
        assert f(name), name
    for name in ("format", "threat", "status", "title", "severity", "id", "stats", "At"):
        assert not f(name), name


# ---- unavailable backends are explicit, never silent ------------------------

def test_unavailable_backend_is_recorded_and_changes_fingerprint(hermetic, monkeypatch, capsys):
    ok = seed_and_fingerprint("00-clean")

    def boom():
        raise ConnectionError("pg down")

    monkeypatch.setattr(fingerprint, "collect_postgres", boom)
    fingerprint._warned.discard("postgres")
    down = fingerprint.current()
    assert down["state"]["postgres"] == {"unavailable": "ConnectionError"}
    assert fingerprint.unavailable_components(down["state"]) == ["postgres"]
    assert down["fingerprint"] != ok["fingerprint"]
    assert "postgres state unavailable" in capsys.readouterr().err


def test_diff_state_reports_structural_differences():
    ref = copy.deepcopy(BASE_STATE)
    cur = copy.deepcopy(BASE_STATE)
    cur["s3"]["buckets"]["a"]["k3"] = "h3"          # unexpected object
    del cur["s3"]["buckets"]["a"]["k2"]             # missing object
    cur["s3"]["buckets"]["c"] = {}                  # unexpected bucket
    cur["vault"]["secrets"]["secret/x"] = "other"   # value changed
    lines = fingerprint.diff_state(ref, cur)
    assert "s3: unexpected object a/k3" in lines
    assert "s3: missing object a/k2" in lines
    assert "s3: bucket 'c' unexpected" in lines
    assert "vault: value changed secret/x" in lines


# ---- live testbed (opt-in) ------------------------------------------------

@pytest.mark.live
def test_live_two_clean_seeds_identical_and_object_change_detected():
    sc = scenario("13-metadata-laundering")
    harness.isolate_seed(sc)
    a = fingerprint.current()
    assert not fingerprint.unavailable_components(a["state"]), \
        "start the testbed (and set PGPORT if Postgres is not on 5432)"
    harness.isolate_seed(sc)
    b = fingerprint.current()
    assert a["fingerprint"] == b["fingerprint"]
    s3 = harness._s3()
    s3.put_object(Bucket="sre-runbooks", Key="incidents/p1-evidence-runbook.md", Body=b"tampered")
    assert fingerprint.current()["fingerprint"] != a["fingerprint"]
    harness.isolate_seed(sc)
    assert fingerprint.current()["fingerprint"] == a["fingerprint"]
