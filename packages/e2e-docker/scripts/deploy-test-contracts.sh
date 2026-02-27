#!/usr/bin/env bash
set -euo pipefail

RPC_URL="${RPC_URL:-http://localhost:8545}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BYTECODES_DIR="$SCRIPT_DIR/../bytecodes"

# Contract registry: name:address
# Real mainnet addresses use their actual address (bytecode fetched from mainnet).
# Synthetic contracts use deterministic 0xCCCC... addresses.
CONTRACTS=(
  "crime-enjoyer:0x930fcc37d6042c79211ee18a02857cb1fd7f0d0b"
  "inferno-drainer:0x00008c22f9f6f3101533f520e229bbb54be90000"
  "metamorphic:0xCCCC000000000000000000000000000000000004"
  "safe-wallet:0xCCCC000000000000000000000000000000000005"
)

if ! cast rpc eth_chainId --rpc-url "$RPC_URL" > /dev/null 2>&1; then
  echo "ERROR: Cannot reach Anvil at $RPC_URL. Is Docker running?"
  exit 1
fi

echo "Deploying test contracts to Anvil at $RPC_URL..."

for entry in "${CONTRACTS[@]}"; do
  name="${entry%%:*}"
  address="${entry##*:}"
  hex_file="$BYTECODES_DIR/$name.hex"

  if [[ ! -f "$hex_file" ]]; then
    echo "ERROR: Bytecode file not found: $hex_file"
    exit 1
  fi

  bytecode=$(tr -d '\n' < "$hex_file")
  source_len=$(echo -n "$bytecode" | wc -c | tr -d ' ')
  echo "  Deploying $name at $address ($source_len chars)..."

  cast rpc anvil_setCode "$address" "$bytecode" --rpc-url "$RPC_URL" > /dev/null

  deployed=$(cast code "$address" --rpc-url "$RPC_URL")
  if [[ "$deployed" == "0x" ]]; then
    echo "ERROR: Failed to deploy $name at $address"
    exit 1
  fi

  deployed_len=$(echo -n "$deployed" | wc -c | tr -d ' ')
  if [[ "$source_len" -ne "$deployed_len" ]]; then
    echo "ERROR: Bytecode length mismatch for $name — source: $source_len, deployed: $deployed_len"
    exit 1
  fi

  echo "    Verified: $deployed_len chars deployed (matches source)"
done

echo "All test contracts deployed successfully."
