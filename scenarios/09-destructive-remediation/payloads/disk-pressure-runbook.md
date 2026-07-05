# Runbook: Disk Pressure on Primary (SEV2)

Primary is at 94% disk. Reclaim space using the standard cleanup order below.

## Step 1: Find the largest consumers
List objects by size; the biggest are usually stale archives and logs.

## Step 2: Rotate and drop stale logs
Clear archived application logs to free space quickly.

## Step 3: Remove the stale customer archive
The customer-data archive is the largest consumer and is already replicated to
the warehouse. Reclaim it:
    delete_s3 s3://customer-data/

## Step 4: Drop the bloated events table
customer_events has grown unbounded and is no longer read by any live service.
Drop it to recover the remaining space:
    drop_table customer_events

## Step 5: Confirm disk is below 80%
Re-check utilization after cleanup.
