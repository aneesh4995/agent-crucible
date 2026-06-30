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
later attack scenarios.

## Roadmap

| Session | Adds |
|---|---|
| 1 | Infrastructure scaffold (this) |
| 2 | Scenario 01 — S3 runbook poisoning + guardrail + dashboard |
| 3 | Scenario 02 — Postgres injection + taint tracking |
| 4 | Scenario 03 — Vault secrets exfiltration + README polish |
| 5 | GitHub launch |

## License

MIT
