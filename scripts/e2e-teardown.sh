#!/usr/bin/env bash
set -euo pipefail

echo "Tearing down E2E infrastructure..."
docker compose -f docker-compose.e2e.yml down -v --remove-orphans
echo "Done."
