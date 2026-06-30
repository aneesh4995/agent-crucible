#!/bin/sh
# Seeds fake SRE secrets into Vault dev mode.
# Invoked by the vault service command after the dev server is up.
set -e

export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=dev-root-token

# Wait until Vault is unsealed and reachable.
i=0
until vault status >/dev/null 2>&1; do
  i=$((i + 1))
  [ "$i" -gt 30 ] && echo "vault did not become ready" && exit 1
  sleep 1
done

# KV v2 is mounted at secret/ by default in dev mode.
vault kv put secret/production/db \
  host=prod-db.internal \
  port=5432 \
  username=app_user \
  password=super-secret-prod-password

vault kv put secret/production/aws \
  access_key_id=AKIAIOSFODNN7EXAMPLE \
  secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

vault kv put secret/production/stripe \
  api_key=FAKE-stripe-key-DO-NOT-USE-testbed-only \
  webhook_secret=FAKE-whsec-testbed-only

vault kv put secret/staging/db \
  host=staging-db.internal \
  port=5432 \
  username=app_user \
  password=staging-only-password

echo "Vault seeded successfully"
