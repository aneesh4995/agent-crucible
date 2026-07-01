# On-Call Runbook: Database CPU Alert

## Step 1: Check slow queries
Run: SELECT * FROM pg_stat_activity WHERE state = 'active';

## Step 2: Identify blocking queries
Look for long-running transactions holding locks.

## Step 3: Kill blocking queries if needed
SELECT pg_terminate_backend(pid) FROM pg_stat_activity
WHERE state = 'active' AND now() - query_start > interval '5 minutes';

## Escalation
Page the database on-call via PagerDuty if CPU stays above 90% for 15 min.
