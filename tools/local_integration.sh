#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d)
trap 'kill ${SERVER_PID:-} ${PYTHON_PID:-} 2>/dev/null || true; rm -rf "$TMP"' EXIT

FINGERPRINT=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
SEED=0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
KEYGEN=$(cargo run --quiet --manifest-path "$ROOT/tools/auth-keygen/Cargo.toml" -- --seed-hex "$SEED")
PUBLIC=$(printf '%s\n' "$KEYGEN" | sed -n 's/^public_key_hex=//p')
PRIVATE=$(printf '%s\n' "$KEYGEN" | sed -n 's/^private_seed_hex=//p')
test "${#PUBLIC}" -eq 64
test "$PRIVATE" = "$SEED"
printf '%s %s\n' "$FINGERPRINT" "$PUBLIC" > "$TMP/authorized_keys"

"$ROOT/target/release/ztsec-server" \
  --no-onion \
  --local-listen 127.0.0.1:4793 \
  --authorized-keys "$TMP/authorized_keys" \
  --local-socket "$TMP/telemetry.sock" \
  --path /ztsec >"$TMP/server.out" 2>"$TMP/server.err" &
SERVER_PID=$!

for _ in $(seq 1 100); do
  test -S "$TMP/telemetry.sock" && break
  sleep 0.1
done
test -S "$TMP/telemetry.sock"

ZTSEC_IPC_SOCKET="$TMP/telemetry.sock" python3 "$ROOT/telemetry_service.py" >"$TMP/python.out" 2>"$TMP/python.err" &
PYTHON_PID=$!

ZTSEC_LOAD_ENDPOINT=ws://127.0.0.1:4793/ztsec \
ZTSEC_LOAD_CONNECTIONS=8 \
ZTSEC_LOAD_DURATION_SECS=2 \
ZTSEC_LOAD_CONNECT_CONCURRENCY=8 \
ZTSEC_LOAD_PRIVATE_KEY_HEX="$SEED" \
ZTSEC_LOAD_FINGERPRINT="$FINGERPRINT" \
cargo run --quiet --manifest-path "$ROOT/tools/load-test/Cargo.toml" --release

for _ in $(seq 1 100); do
  grep -q '"agent_id":"' "$TMP/python.out" && break
  sleep 0.1
done
grep -q '"agent_id":"' "$TMP/python.out"
grep -q '"CPU":"CPU"' "$TMP/python.out"
printf 'local integration: PASS\n'
