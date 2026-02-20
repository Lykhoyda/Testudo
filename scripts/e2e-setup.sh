#!/usr/bin/env bash
set -euo pipefail

COMPOSE_FILE="docker-compose.e2e.yml"

echo "Starting E2E infrastructure..."
docker compose -f "$COMPOSE_FILE" up -d --build --wait

echo "Running migrations..."
docker compose -f "$COMPOSE_FILE" exec -T testudo-api node dist/db/migrate.js

echo "Seeding test data..."
docker compose -f "$COMPOSE_FILE" exec -T postgres psql -U testudo -d testudo_test <<'SQL'
INSERT INTO threats (address, chain_id, threat_type, threat_level, confidence, sources)
VALUES
  ('0x930fcc37d6042c79211ee18a02857cb1fd7f0d0b', 1, 'ETH_DRAINER', 'CRITICAL', 1.00, ARRAY['testudo-test-data']),
  ('0xa85d90b8febc092e11e75bf8f93a7090e2ed04de', 1, 'INFERNO_DRAINER', 'CRITICAL', 1.00, ARRAY['testudo-test-data']),
  ('0x0000db5c8b030ae20308ac975898e09741e70000', 1, 'INFERNO_DRAINER', 'CRITICAL', 1.00, ARRAY['testudo-test-data']),
  ('0x00008c22f9f6f3101533f520e229bbb54be90000', 1, 'INFERNO_DRAINER', 'CRITICAL', 1.00, ARRAY['testudo-test-data'])
ON CONFLICT (address) DO NOTHING;

INSERT INTO safe_addresses (address, chain_id, name, category, is_delegation_safe, sources, confidence)
VALUES
  ('0x1111111111111111111111111111111111111111', 1, 'Test Safe 1', 'DEFI_PROTOCOL', true, ARRAY['test-seed'], 0.95),
  ('0x2222222222222222222222222222222222222222', 1, 'Test Safe 2', 'STABLECOIN', true, ARRAY['test-seed'], 0.90),
  ('0x3333333333333333333333333333333333333333', 1, 'Test Revoked', 'DEFI_PROTOCOL', true, ARRAY['test-seed'], 0.85)
ON CONFLICT DO NOTHING;

INSERT INTO revocations (address, chain_id, reason, revoked_by, is_active)
SELECT '0x3333333333333333333333333333333333333333', 1, 'test_revocation', 'test-seed', true
WHERE NOT EXISTS (
  SELECT 1 FROM revocations WHERE address = '0x3333333333333333333333333333333333333333' AND chain_id = 1
);
SQL

echo "E2E infrastructure ready."
echo "  Anvil:    http://localhost:8545"
echo "  Postgres: localhost:5433"
echo "  API:      http://localhost:3001"
