#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== Tearing down integration test environment ==="

docker compose -f "${SCRIPT_DIR}/docker-compose.yml" down --remove-orphans 2>/dev/null || true

echo "=== Cleanup complete ==="
