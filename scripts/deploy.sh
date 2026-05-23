#!/usr/bin/env bash
# Safe Sender — deploy script.
#
# Reads encrypted secrets from .env.enc (sops + age), decrypts to a tmpfs
# path (/run, wiped on reboot), and brings up the prod stack. Never writes
# plaintext secrets to persistent disk.
#
# Requirements on host:
#   - sops, age installed
#   - age private key at /root/.config/sops/age/keys.txt (chmod 600)
#   - .sops.yaml + .env.enc present in repo root
#
# Usage:  ./scripts/deploy.sh           # build + up
#         ./scripts/deploy.sh restart   # decrypt + restart only
#         ./scripts/deploy.sh down      # stop stack, wipe decrypted env

set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_DIR"

ENC_FILE=".env.enc"
RUNTIME_ENV="/run/safe-sender.env"
COMPOSE_FILE="docker-compose.prod.yml"

require() {
  command -v "$1" >/dev/null 2>&1 || { echo "ERROR: $1 not installed" >&2; exit 1; }
}
require sops
require docker

cleanup_env() {
  # Best-effort secure wipe of the runtime env file
  if [ -f "$RUNTIME_ENV" ]; then
    shred -u "$RUNTIME_ENV" 2>/dev/null || rm -f "$RUNTIME_ENV"
  fi
}

decrypt_env() {
  if [ ! -f "$ENC_FILE" ]; then
    echo "ERROR: $ENC_FILE not found" >&2
    exit 1
  fi
  umask 077
  sops --decrypt --input-type dotenv --output-type dotenv "$ENC_FILE" > "$RUNTIME_ENV"
  chmod 600 "$RUNTIME_ENV"
}

case "${1:-up}" in
  up)
    decrypt_env
    docker compose --env-file "$RUNTIME_ENV" -f "$COMPOSE_FILE" up -d --build
    # NOTE: do NOT wipe $RUNTIME_ENV — compose re-reads it on subsequent
    # `docker compose` invocations against the same project. Tmpfs wipes
    # it on reboot. Re-run this script after any reboot.
    ;;
  restart)
    decrypt_env
    docker compose --env-file "$RUNTIME_ENV" -f "$COMPOSE_FILE" up -d
    ;;
  down)
    if [ -f "$RUNTIME_ENV" ]; then
      docker compose --env-file "$RUNTIME_ENV" -f "$COMPOSE_FILE" down || true
    else
      docker compose -f "$COMPOSE_FILE" down || true
    fi
    cleanup_env
    ;;
  *)
    echo "Usage: $0 [up|restart|down]" >&2
    exit 2
    ;;
esac
