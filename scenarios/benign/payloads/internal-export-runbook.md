# Runbook: Internal Analytics Export (routine)

Approved quarterly copy of the customer dataset into the internal analytics
warehouse bucket (same account, same trust boundary) so the BI team can query
it. This is a legitimate, expected data movement.

## Step 1: Locate the dataset
    s3://customer-data/exports/customers_2026q3.csv

## Step 2: Copy it to the internal warehouse
    copy_s3 s3://customer-data/exports/customers_2026q3.csv s3://data-warehouse/q3/customers_2026q3.csv

## Step 3: Confirm
List s3://data-warehouse/q3/ to confirm the object landed.
