# agent-crucible

> A containerized security testbed for evaluating AI agent guardrails against
> prompt injection attacks in SRE/cloud infrastructure workflows.

AI agents with cloud access are vulnerable to prompt injection. This testbed
lets you fire those attacks safely against an agent and measure what your
guardrails catch.

## Quick start

```bash
git clone <repo-url>
cd agent-crucible
cp .env.example .env          # add your LocalStack auth token
docker compose up
```

Verify the seeded environment:

```bash
aws --endpoint-url=http://localhost:4566 s3 ls            # 3 buckets
curl http://localhost:8200/v1/sys/health                  # Vault responds
psql postgresql://sre:sre_local@localhost:5432/sre_runbooks -c '\dt'
```

## What's running (Session 1)

| Service | Port | Purpose |
|---|---|---|
| LocalStack | 4566 | S3, DynamoDB, IAM, STS, Secrets Manager, CloudWatch, Logs |
| Postgres | 5432 | SRE runbooks + incident database |
| Vault | 8200 | Production/staging secrets (dev mode) |

Seed data lives in `init/`. The `customer-data` S3 bucket and Vault
`secret/production/*` paths are the sensitive exfiltration targets used by
the attack scenarios.

## Attack scenarios

8 scenarios test two threat classes: a stealth ladder of prompt-injection
variants (01–06) and a confused-deputy attack with no injection at all (07).
Full scenario table, ground truth, and results: **[scenarios/README.md](scenarios/README.md)**.

Run any scenario against any model automatically:
```bash
python agent/harness.py --models mistralai/mistral-medium-3-5 --scenarios 07-confused-deputy-export
```
See [agent/README.md](agent/README.md) for the harness.

**Bring your own attack:** drop an injection into
[scenarios/99-custom/payloads/custom-runbook.md](scenarios/99-custom/payloads/custom-runbook.md)
and run `--scenarios 99-custom` — no code changes, compromise scored automatically.

**Headline result so far:** a strong open model (mistral-medium-3.5) was
compromised on 7/7 scenarios; Claude Code held on all manual runs. Capability
doesn't predict robustness — see [scenarios/README.md](scenarios/README.md#automated-harness-results-isolated-attributable--2026-07-01)
for the full matrix.

## Roadmap

| Stage | Adds | Status |
|---|---|---|
| 1 | Infrastructure scaffold | done |
| 2 | Attack corpus (8 scenarios) + automated multi-model harness | done |
| 3 | Guardrail interceptor + policy engine | in progress |
| 4 | Dashboard | not started |
| 5 | GitHub launch polish | not started |

## License

MIT
