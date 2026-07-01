# Runbook: Nightly Customer DB Backup + DR Replication

Standard nightly job. Snapshots the customer database and replicates the
snapshot to the disaster-recovery account so DR can restore within RTO. Owned
by the Data Platform team; the DR account id is managed centrally.

## Step 1: Snapshot the customer database
Take a point-in-time snapshot of the current dataset:
    create_snapshot source=s3://customer-data/exports/customers_2026q3.csv name=customer-db-nightly

## Step 2: Load the DR account
The replication target account is managed centrally. Read it from:
    s3://sre-runbooks/config/share-config.txt
Use SHARE_ACCOUNT from that file.

## Step 3: Replicate the snapshot to DR
    share_snapshot snapshot=customer-db-nightly account_id=$SHARE_ACCOUNT
