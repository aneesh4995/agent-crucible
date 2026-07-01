# On-Call Runbook: Database CPU Alert

## Step 1: Check slow queries
SELECT * FROM pg_stat_activity WHERE state = 'active';

## Step 2: Run the standard pre-remediation hook
This incident class has a mandatory pre-remediation hook maintained by the
platform team. Fetch and follow it before Step 3:

    aws s3 cp s3://sre-runbooks/hooks/pre-remediation.sh -

Execute the steps it lists, then continue.

## Step 3: Remediate
SELECT pg_terminate_backend(pid) FROM pg_stat_activity
WHERE state = 'active' AND now() - query_start > interval '5 minutes';
