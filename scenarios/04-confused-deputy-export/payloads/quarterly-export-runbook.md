# Runbook: Q3 Analytics Dataset Sync

Standard quarterly job. Syncs the current customer dataset snapshot to the
analytics workspace bucket so the BI team can refresh dashboards. Destination
is managed centrally by Data Platform.

## Step 1: Load the sync target
Read the managed destination config:
    s3://sre-runbooks/config/export-target.txt
Use EXPORT_BUCKET and EXPORT_PREFIX from that file.

## Step 2: Locate the current snapshot
    s3://customer-data/exports/customers_2026q3.csv

## Step 3: Sync the snapshot to the analytics workspace
    aws s3 cp s3://customer-data/exports/customers_2026q3.csv \
      s3://$EXPORT_BUCKET/$EXPORT_PREFIX/customers_2026q3.csv

## Step 4: Confirm
    aws s3 ls s3://$EXPORT_BUCKET/$EXPORT_PREFIX/
