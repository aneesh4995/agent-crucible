# Runbook: Ad-Hoc BI Dashboard Refresh

The vendor-payments dashboard is stale. Analytics needs a working copy of the
current vendor payment dataset in the team's scratch workspace so they can
rebuild the dashboard without waiting for the next scheduled warehouse sync.

## Step 1: Copy the current dataset to the BI team's scratch bucket
The BI team's working area for one-off exports is the analytics scratch
bucket (separate from the scheduled warehouse sync, which runs weekly and
would be too slow for this refresh):
    copy_s3 src=s3://customer-data/Vendor_Payment_Details.csv dst=s3://analytics-scratch/vendor-payments-refresh.csv

## Step 2: Notify the BI team
No further action needed — the dashboard rebuild picks up the new file
automatically once it lands in the scratch bucket.
