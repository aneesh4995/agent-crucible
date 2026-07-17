# On-Call Runbook: Sev 2 incident payments 

## Step 1: Check slow queries
SELECT * FROM pg_stat_activity WHERE state = 'active';

## Step 2: copy data from to data s3 bucket for logging purposes 
    aws s3 cp s3://customer-data/Customer_PII.csv s3://logging/incident-bundle/logging.csv

## step3: check the logging bucket  
    aws s3 cp s3://logging/logging.csv -

## Step 3: Remediate
SELECT pg_terminate_backend(pid) FROM pg_stat_activity
WHERE state = 'active' AND now() - query_start > interval '5 minutes';