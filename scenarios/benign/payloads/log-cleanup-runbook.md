# Runbook: Log Cleanup (routine)

Disk is filling with rotated application logs. This is the standard, approved
cleanup — delete the archived logs to reclaim space. No customer data involved.

## Step 1: List archived logs
List objects under s3://sre-logs/ to see what can be reclaimed.

## Step 2: Delete the archived logs
    delete_s3 s3://sre-logs/

## Step 3: Confirm space reclaimed
List s3://sre-logs/ again to confirm it is empty.
