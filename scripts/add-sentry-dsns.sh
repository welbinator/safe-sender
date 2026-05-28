#!/usr/bin/env bash
# Add Sentry DSNs to .env.enc.
#
# Approach: decrypt → strip any existing Sentry keys → append → re-encrypt.
# This is more reliable than `sops --set` on dotenv files (which assumes JSON).
#
# Idempotent: re-running with the same values replaces them cleanly.
#
# Usage:  ./scripts/add-sentry-dsns.sh <backend-dsn> <smtp-dsn> <dashboard-dsn>

set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_DIR"

BACKEND_DSN="${1:-}"
SMTP_DSN="${2:-}"
DASHBOARD_DSN="${3:-}"

if [ -z "$BACKEND_DSN" ] || [ -z "$SMTP_DSN" ] || [ -z "$DASHBOARD_DSN" ]; then
  echo "usage: $0 <backend-dsn> <smtp-dsn> <dashboard-dsn>" >&2
  exit 2
fi

command -v sops >/dev/null 2>&1 || { echo "ERROR: sops not installed" >&2; exit 1; }

ENC=".env.enc"
TMP_PLAIN=".sentry-staging.env"
trap 'shred -u "$TMP_PLAIN" 2>/dev/null || rm -f "$TMP_PLAIN"' EXIT

# Decrypt → drop old Sentry keys (idempotent re-runs) → append new ones.
# Use a filename matching .sops.yaml's creation_rules so re-encryption picks
# up the correct recipients.
sops --decrypt --input-type dotenv --output-type dotenv "$ENC" \
  | grep -vE '^(SENTRY_DSN_BACKEND|SENTRY_DSN_SMTP|VITE_SENTRY_DSN|SENTRY_ENVIRONMENT|SENTRY_TRACES_SAMPLE_RATE)=' \
  > "$TMP_PLAIN"

cat >> "$TMP_PLAIN" <<EOF
SENTRY_DSN_BACKEND=$BACKEND_DSN
SENTRY_DSN_SMTP=$SMTP_DSN
VITE_SENTRY_DSN=$DASHBOARD_DSN
SENTRY_ENVIRONMENT=production
SENTRY_TRACES_SAMPLE_RATE=0.05
EOF

# Re-encrypt. sops reads creation_rules from .sops.yaml based on filename.
sops --encrypt --input-type dotenv --output-type dotenv "$TMP_PLAIN" > "$ENC.new"
mv "$ENC.new" "$ENC"

echo "✓ Sentry DSNs added to .env.enc"
echo
echo "Verify:"
echo "  sops --decrypt --input-type dotenv --output-type dotenv .env.enc | grep -E 'SENTRY|VITE_SENTRY'"
