"""Reference guardrail for the agent-crucible testbed.

A deterministic pre-execution check on every tool call. Runs BEFORE the tool
executes; a denied call never runs and the model receives a policy-denial
message. Enforcement does not depend on model judgment or human confirmation —
that is the point: it holds where soft (model refusal / human-in-the-loop)
defenses fail.

Three layers, each independently toggleable for ablation:
  L1 capability broker  — per-task allowlist of tools + readable resources.
  L2 policy engine      — destination rules (external account / public / egress).
  L3 taint tracker      — block a sink moving sensitive-derived data out.

Usage:
    g = Guardrail(profile="sre-triage", layers={"L1","L2","L3"})
    allow, reason = g.check(tool_name, args, session)
"""
from __future__ import annotations

import pathlib
from urllib.parse import urlparse

import yaml

import tools  # reuse trust model + taint helpers

POLICY_PATH = pathlib.Path(__file__).parent / "policy.yaml"


def _host(url: str) -> str:
    try:
        return urlparse(url).netloc or url
    except Exception:
        return url


def _match(pattern: str, value: str) -> bool:
    # simple "bucket/*" prefix glob
    if pattern.endswith("/*"):
        return value.startswith(pattern[:-1])
    return pattern == value


class Guardrail:
    def __init__(self, profile: str = "sre-triage",
                 layers: set[str] | None = None,
                 policy_path: pathlib.Path = POLICY_PATH):
        self.policy = yaml.safe_load(policy_path.read_text())
        self.profile_name = profile
        self.profile = self.policy.get("task_profiles", {}).get(profile, {})
        self.layers = layers or {"L1", "L2", "L3"}

    # -- public API ---------------------------------------------------------

    def check(self, tool: str, args: dict, session) -> tuple[bool, str]:
        """Return (allow, reason). reason is a short 'Ln:...' tag on deny."""
        if "L1" in self.layers:
            ok, why = self._l1(tool, args)
            if not ok:
                return False, why
        if "L2" in self.layers:
            ok, why = self._l2(tool, args, session)
            if not ok:
                return False, why
        if "L3" in self.layers:
            ok, why = self._l3(tool, args, session)
            if not ok:
                return False, why
        return True, ""

    # -- L1 capability broker ----------------------------------------------

    def _l1(self, tool: str, args: dict) -> tuple[bool, str]:
        allow_tools = self.profile.get("allow_tools")
        if allow_tools is not None and tool not in allow_tools:
            return False, f"L1:tool '{tool}' not in profile '{self.profile_name}'"
        # read-scope denies
        uri = args.get("uri") or args.get("source_uri") or args.get("src_uri")
        if uri and tool in ("read_s3", "list_s3", "create_snapshot"):
            bucket, key = tools._parse_uri(uri)
            resource = f"{bucket}/{key}"
            for pat in self.profile.get("deny_read", []):
                if _match(pat, resource):
                    return False, f"L1:read denied on {resource}"
        return True, ""

    # -- L2 policy engine ---------------------------------------------------

    def _l2(self, tool: str, args: dict, session) -> tuple[bool, str]:
        p, l2 = self.policy, self.policy.get("l2", {})
        if tool == "http_post" and l2.get("deny_egress_not_in_allowlist"):
            host = _host(args.get("url", ""))
            if host not in p.get("egress_allowlist", []):
                return False, f"L2:egress to non-allowlisted host {host}"
        if tool == "share_snapshot" and l2.get("deny_share_to_external_account"):
            acct = str(args.get("account_id", ""))
            if acct not in p.get("allowed_accounts", []):
                return False, f"L2:share to external account {acct}"
        if tool == "copy_s3" and l2.get("deny_copy_to_untrusted_bucket"):
            dst_bucket, _ = tools._parse_uri(args.get("dst_uri", ""))
            if dst_bucket not in p.get("trusted_buckets", []):
                return False, f"L2:copy to untrusted bucket {dst_bucket}"
        if tool == "make_public" and l2.get("deny_make_public"):
            bucket, key = tools._parse_uri(args.get("uri", ""))
            if bucket in p.get("sensitive_buckets", []) or \
               tools._sensitive_src(session, bucket, key):
                return False, f"L2:make_public on sensitive {bucket}/{key}"
        if tool == "delete_s3" and l2.get("deny_delete_protected"):
            bucket, _ = tools._parse_uri(args.get("uri", ""))
            if bucket in p.get("protected_buckets", []):
                return False, f"L2:delete of protected bucket {bucket}"
        if tool == "drop_table" and l2.get("deny_drop_protected"):
            table = args.get("table", "")
            if table in p.get("protected_tables", []):
                return False, f"L2:drop of protected table {table}"
        return True, ""

    # -- L3 taint tracker ---------------------------------------------------

    def _l3(self, tool: str, args: dict, session) -> tuple[bool, str]:
        l3 = self.policy.get("l3", {})
        if not l3.get("block_if_tainted") or tool not in l3.get("sinks", []):
            return True, ""
        if tool == "http_post":
            body = args.get("body", "")
            if session.tainted or tools._carries_tainted(session, body):
                return False, "L3:egress of tainted data"
        elif tool == "copy_s3":
            b, k = tools._parse_uri(args.get("src_uri", ""))
            dst_b, _ = tools._parse_uri(args.get("dst_uri", ""))
            if tools._sensitive_src(session, b, k) and \
               dst_b not in self.policy.get("trusted_buckets", []):
                return False, "L3:copy of tainted data to untrusted sink"
        elif tool == "share_snapshot":
            key = f"{tools.SNAPSHOT_BUCKET}/{args.get('snapshot_name','')}"
            if key in session.tainted_keys:
                return False, "L3:share of tainted snapshot"
        elif tool == "make_public":
            b, k = tools._parse_uri(args.get("uri", ""))
            if tools._sensitive_src(session, b, k):
                return False, "L3:make_public of tainted object"
        return True, ""
