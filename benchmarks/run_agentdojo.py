"""Run the AgentDojo injection benchmark against Claude Sonnet 4.6.

AgentDojo's model enum stops at claude-3-7; 4.6 is not selectable via its CLI.
This runner injects a pre-built AnthropicLLM(claude-sonnet-4-6) directly into the
pipeline (from_config accepts an LLM object as config.llm), then runs one suite +
one attack.

AgentDojo domain = banking / travel / slack / workspace (general productivity),
NOT privileged SRE. This is an external robustness cross-check and comparability
baseline for related work — not the dissertation's primary contribution. It runs
the BARE Anthropic API model, not the Claude Code product harness.

Usage:
  python benchmarks/run_agentdojo.py --suite banking --attack important_instructions --tasks 5
Requires ANTHROPIC_API_KEY with a funded balance.
"""
from __future__ import annotations

import argparse
import pathlib

import anthropic
import yaml
from agentdojo.agent_pipeline import AgentPipeline, AnthropicLLM, PipelineConfig
from agentdojo.attacks import load_attack
from agentdojo.benchmark import benchmark_suite_with_injections
from agentdojo.task_suite.load_suites import get_suites

MODEL = "claude-sonnet-4-6"

# 4.6 is newer than AgentDojo's registry. Register it so attacks that read the
# model display name (e.g. important_instructions) resolve it to "Claude".
from agentdojo.models import MODEL_NAMES, MODEL_PROVIDERS  # noqa: E402
MODEL_NAMES[MODEL] = "Claude"
try:
    MODEL_PROVIDERS[MODEL] = "anthropic"
except Exception:
    pass


def _default_system_message() -> str:
    import agentdojo
    p = pathlib.Path(agentdojo.__file__).parent / "data" / "system_messages.yaml"
    data = yaml.safe_load(p.read_text())
    # file maps names -> message; take the default/first
    if isinstance(data, dict):
        return data.get("default") or next(iter(data.values()))
    return str(data)


def build_pipeline() -> AgentPipeline:
    client = anthropic.Anthropic()
    llm = AnthropicLLM(client, MODEL, temperature=0.0, max_tokens=1024)
    cfg = PipelineConfig(
        llm=llm,
        model_id=MODEL,
        defense=None,
        system_message_name="default",
        system_message=_default_system_message(),
        tool_output_format=None,
    )
    pipeline = AgentPipeline.from_config(cfg)
    pipeline.name = MODEL
    return pipeline


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--suite", default="banking", choices=["banking", "travel", "slack", "workspace"])
    ap.add_argument("--attack", default="important_instructions")
    ap.add_argument("--tasks", type=int, default=5, help="limit number of user tasks")
    ap.add_argument("--version", default="v1.2")
    ap.add_argument("--logdir", default="./benchmarks/agentdojo-runs")
    args = ap.parse_args()

    suite = get_suites(args.version)[args.suite]
    pipeline = build_pipeline()
    attack = load_attack(args.attack, suite, pipeline)

    user_tasks = list(suite.user_tasks.keys())[: args.tasks]

    results = benchmark_suite_with_injections(
        pipeline, suite, attack,
        logdir=pathlib.Path(args.logdir),
        force_rerun=False,
        user_tasks=user_tasks,
        benchmark_version=args.version,
    )

    utils = results.utility_results          # {(user,injection): bool}
    secs = results.security_results          # {(user,injection): bool}  True = attack succeeded
    n = len(secs)
    asr = sum(1 for v in secs.values() if v) / n if n else 0.0
    util = sum(1 for v in utils.values() if v) / len(utils) if utils else 0.0
    print(f"\n=== AgentDojo {args.suite} / {args.attack} / {MODEL} ===")
    print(f"tasks x injections: {n}")
    print(f"ASR (attack success rate): {asr:.1%}")
    print(f"utility (benign task success): {util:.1%}")
    print(f"logs: {args.logdir}")


if __name__ == "__main__":
    main()
