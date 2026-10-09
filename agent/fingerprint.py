"""Deterministic fingerprint of the seeded testbed state.

The harness resets and seeds the environment before every trial. This module
answers one question: *is the state the agent is about to run against exactly the
state we intended?* It reads the environment back and reduces it to a SHA-256.

Covered state (each backend is a separate "component"):

  s3        every bucket and every object key, with the SHA-256 of the object
            body. Bucket existence counts (an empty bucket is state). ETags,
            LastModified, ACLs and owner ids are NOT read.
  dynamodb  every table's key schema plus its items (typed DynamoDB values,
            set members sorted, binary base64-encoded). Attributes whose name
            marks them as a timestamp are dropped.
  postgres  the fixture tables ``runbooks``, ``incidents`` and ``audit_log``:
            column names (in ordinal order) and all rows, rows sorted by their
            canonical JSON so DB collation cannot change the hash. Columns of a
            time type (timestamp / date / time / interval) are dropped.
  vault     every KV-v2 secret path under ``secret/`` with the SHA-256 of the
            canonical JSON of its data. Secret VALUES never appear in the
            fingerprint state, only their hashes. KV metadata (created_time,
            version) is not read.

Nothing here depends on wall-clock time, request ids or random values.

A backend that cannot be read is recorded as ``{"unavailable": "<reason>"}`` and
a warning is printed: the trial still runs, but its fingerprint will not match a
reference taken with all backends up, so the problem is visible, not silent.

The canonical form is ``json.dumps(sort_keys=True, separators=(",", ":"))``.
Bump ``SCHEMA_VERSION`` if the collected structure ever changes.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.request

SCHEMA_VERSION = 1

# Fixture tables the Postgres component covers (see init/seed-postgres.sql).
POSTGRES_TABLES = ("runbooks", "incidents", "audit_log")
_PG_TIME_TYPES = {
    "timestamp without time zone", "timestamp with time zone",
    "date", "time without time zone", "time with time zone", "interval",
}
# DynamoDB has no declared time type, so drop attributes whose NAME says time.
_DDB_TIME_ATTR = re.compile(
    r"^(?i:ts|timestamp|time|created|updated|modified|last_?updated)$"  # exact names
    r"|_at$"            # created_at, updated_at, ...
    r"|[a-z]At$")       # camelCase createdAt, updatedAt (case-sensitive)

_warned: set[str] = set()


def _warn_once(component: str, reason: str) -> None:
    if component not in _warned:
        _warned.add(component)
        print(f"[fingerprint] WARNING: {component} state unavailable ({reason}); "
              f"fingerprints from this run will NOT match a reference taken with "
              f"all backends up.", file=sys.stderr)


# --------------------------------------------------------------------------
# canonical hashing (pure)
# --------------------------------------------------------------------------

def canon(obj) -> bytes:
    """Canonical JSON bytes: sorted keys, no whitespace, ASCII-safe."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str).encode("ascii")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fingerprint(state: dict) -> dict:
    """Reduce a collected state dict to {"fingerprint": hex, "components": {...}}.

    Pure function: same state in -> same hashes out, on any machine.
    """
    components = {name: sha256_hex(canon(part)) for name, part in sorted(state.items())}
    overall = sha256_hex(canon({"schema_version": SCHEMA_VERSION, "components": components}))
    return {"fingerprint": overall, "components": components}


# --------------------------------------------------------------------------
# collectors (read the live environment)
# --------------------------------------------------------------------------

def _s3_client():
    import boto3
    return boto3.client(
        "s3",
        endpoint_url=os.environ.get("LOCALSTACK_ENDPOINT", "http://localhost:4566"),
        aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID", "test"),
        aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY", "test"),
        region_name=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"),
    )


def _ddb_client():
    import boto3
    return boto3.client(
        "dynamodb",
        endpoint_url=os.environ.get("LOCALSTACK_ENDPOINT", "http://localhost:4566"),
        aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID", "test"),
        aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY", "test"),
        region_name=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"),
    )


def collect_s3(client=None) -> dict:
    """{"buckets": {bucket: {key: sha256(body)}}} for every bucket."""
    s3 = client or _s3_client()
    buckets: dict[str, dict[str, str]] = {}
    for b in sorted(x["Name"] for x in s3.list_buckets().get("Buckets", [])):
        objs: dict[str, str] = {}
        token = None
        while True:
            kw = {"Bucket": b}
            if token:
                kw["ContinuationToken"] = token
            page = s3.list_objects_v2(**kw)
            for o in page.get("Contents", []):
                body = s3.get_object(Bucket=b, Key=o["Key"])["Body"].read()
                objs[o["Key"]] = hashlib.sha256(body).hexdigest()
            if not page.get("IsTruncated"):
                break
            token = page.get("NextContinuationToken")
        buckets[b] = objs
    return {"buckets": buckets}


def _norm_ddb_value(v):
    """Make a typed DynamoDB value order-stable and JSON-safe."""
    if isinstance(v, dict):
        out = {}
        for t, x in v.items():
            if t in ("SS", "NS"):
                out[t] = sorted(x)
            elif t == "BS":
                out[t] = sorted(base64.b64encode(b).decode() for b in x)
            elif t == "B":
                out[t] = base64.b64encode(x).decode()
            elif t == "L":
                out[t] = [_norm_ddb_value(i) for i in x]
            elif t == "M":
                out[t] = {k: _norm_ddb_value(i) for k, i in x.items()}
            else:
                out[t] = x
        return out
    return v


def collect_dynamodb(client=None) -> dict:
    """{"tables": {name: {"key_schema": ..., "item_count": n, "items_sha256": h}}}"""
    ddb = client or _ddb_client()
    tables: dict[str, dict] = {}
    names, token = [], None
    while True:
        page = ddb.list_tables(**({"ExclusiveStartTableName": token} if token else {}))
        names += page.get("TableNames", [])
        token = page.get("LastEvaluatedTableName")
        if not token:
            break
    for name in sorted(names):
        desc = ddb.describe_table(TableName=name)["Table"]
        key_schema = sorted((k["AttributeName"], k["KeyType"]) for k in desc["KeySchema"])
        items, start = [], None
        while True:
            page = ddb.scan(TableName=name, **({"ExclusiveStartKey": start} if start else {}))
            for item in page.get("Items", []):
                items.append({a: _norm_ddb_value(v) for a, v in item.items()
                              if not _DDB_TIME_ATTR.search(a)})
            start = page.get("LastEvaluatedKey")
            if not start:
                break
        rows = sorted(canon(i).decode() for i in items)
        tables[name] = {"key_schema": key_schema, "item_count": len(rows),
                        "items_sha256": sha256_hex("\n".join(rows).encode())}
    return {"tables": tables}


def _pg_params() -> dict:
    # Defaults match docker-compose.yml (fake testbed credentials).
    return dict(
        host=os.environ.get("PGHOST", "localhost"),
        port=int(os.environ.get("PGPORT", "5432")),
        user=os.environ.get("PGUSER", "sre"),
        password=os.environ.get("PGPASSWORD", "sre_local"),
        dbname=os.environ.get("PGDATABASE", "sre_runbooks"),
        connect_timeout=3,
    )


def collect_postgres(tables=POSTGRES_TABLES) -> dict:
    """{"tables": {name: {"columns": [...], "row_count": n, "rows_sha256": h}}}"""
    import psycopg  # lazy: only needed when this component is collected

    out: dict[str, dict] = {}
    with psycopg.connect(**_pg_params()) as conn, conn.cursor() as cur:
        for t in tables:
            cur.execute(
                "SELECT column_name, data_type FROM information_schema.columns "
                "WHERE table_schema = 'public' AND table_name = %s "
                "ORDER BY ordinal_position", (t,))
            cols = [(c, dt) for c, dt in cur.fetchall()]
            if not cols:
                out[t] = {"missing": True}
                continue
            keep = [c for c, dt in cols if dt not in _PG_TIME_TYPES]
            quoted = ", ".join('"' + c.replace('"', '""') + '"' for c in keep)
            cur.execute(f'SELECT {quoted} FROM public."{t}"')
            rows = sorted(canon(list(r)).decode() for r in cur.fetchall())
            out[t] = {"columns": keep, "row_count": len(rows),
                      "rows_sha256": sha256_hex("\n".join(rows).encode())}
    return {"tables": out}


def _vault_get(path: str, token: str, base: str):
    req = urllib.request.Request(f"{base}/v1/{path}", headers={"X-Vault-Token": token})
    with urllib.request.urlopen(req, timeout=5) as r:  # nosec B310: local testbed
        return json.loads(r.read().decode())


def collect_vault() -> dict:
    """{"secrets": {"secret/<path>": sha256(canonical data)}} for every KV-v2 secret."""
    base = os.environ.get("VAULT_ADDR", "http://localhost:8200").rstrip("/")
    token = os.environ.get("VAULT_TOKEN", "dev-root-token")
    secrets: dict[str, str] = {}

    def walk(prefix: str) -> None:
        try:
            listing = _vault_get(f"secret/metadata/{prefix}?list=true", token, base)
        except urllib.error.HTTPError as e:
            if e.code == 404:  # nothing under this prefix
                return
            raise
        for k in listing["data"]["keys"]:
            if k.endswith("/"):
                walk(prefix + k)
            else:
                path = prefix + k
                try:
                    data = _vault_get(f"secret/data/{path}", token, base)["data"]["data"]
                except urllib.error.HTTPError as e:
                    if e.code == 404:  # metadata present but latest version deleted
                        continue
                    raise
                secrets[f"secret/{path}"] = sha256_hex(canon(data))

    walk("")
    return {"secrets": secrets}


def collect_state() -> dict:
    """Read every backend. Never raises for an unreachable backend."""
    state: dict[str, dict] = {}
    for name, fn in (("s3", collect_s3), ("dynamodb", collect_dynamodb),
                     ("postgres", collect_postgres), ("vault", collect_vault)):
        try:
            state[name] = fn()
        except ImportError as e:
            state[name] = {"unavailable": f"ImportError:{e.name}"}
            _warn_once(name, f"missing module {e.name}")
        except Exception as e:  # noqa: BLE001 - any backend failure must be explicit
            state[name] = {"unavailable": type(e).__name__}
            _warn_once(name, type(e).__name__)
    return state


def current() -> dict:
    """Collect the live environment and fingerprint it.

    Returns {"fingerprint", "components", "state"}; ``state`` is the compact,
    secret-free structure the hashes were computed from (used for diffs).
    """
    state = collect_state()
    return {**fingerprint(state), "state": state}


def unavailable_components(state: dict) -> list[str]:
    return sorted(n for n, part in state.items() if "unavailable" in part)


# --------------------------------------------------------------------------
# explaining a mismatch
# --------------------------------------------------------------------------

def diff_state(ref: dict, cur: dict) -> list[str]:
    """Human-readable differences between two collected states."""
    lines: list[str] = []
    for comp in sorted(set(ref) | set(cur)):
        a, b = ref.get(comp), cur.get(comp)
        if a == b:
            continue
        if a is None or b is None:
            lines.append(f"{comp}: present in {'reference' if b is None else 'current'} only")
            continue
        if "unavailable" in a or "unavailable" in b:
            lines.append(f"{comp}: unavailable (ref={a.get('unavailable')}, cur={b.get('unavailable')})")
            continue
        if comp == "s3":
            ra, rb = a["buckets"], b["buckets"]
            for bucket in sorted(set(ra) | set(rb)):
                if bucket not in ra:
                    lines.append(f"s3: bucket '{bucket}' unexpected")
                elif bucket not in rb:
                    lines.append(f"s3: bucket '{bucket}' missing")
                else:
                    for key in sorted(set(ra[bucket]) | set(rb[bucket])):
                        if key not in ra[bucket]:
                            lines.append(f"s3: unexpected object {bucket}/{key}")
                        elif key not in rb[bucket]:
                            lines.append(f"s3: missing object {bucket}/{key}")
                        elif ra[bucket][key] != rb[bucket][key]:
                            lines.append(f"s3: content changed {bucket}/{key}")
        elif comp == "vault":
            ra, rb = a["secrets"], b["secrets"]
            for path in sorted(set(ra) | set(rb)):
                if path not in ra:
                    lines.append(f"vault: unexpected secret {path}")
                elif path not in rb:
                    lines.append(f"vault: missing secret {path}")
                elif ra[path] != rb[path]:
                    lines.append(f"vault: value changed {path}")
        else:  # dynamodb / postgres: table-level
            ra, rb = a["tables"], b["tables"]
            for t in sorted(set(ra) | set(rb)):
                if ra.get(t) != rb.get(t):
                    lines.append(f"{comp}: table '{t}' differs")
    return lines or ["(states differ but no structural difference isolated)"]
