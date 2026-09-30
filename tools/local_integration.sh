#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d)
LOAD_PIDS=()
cleanup() {
  status=$?
  if [ "$status" -ne 0 ]; then
    echo "local integration failed; collecting service logs" >&2
    for file in "$TMP"/server.out "$TMP"/server.err "$TMP"/python.out "$TMP"/python.err "$TMP"/unicast.out "$TMP"/unicast.err "$TMP"/broadcast.out "$TMP"/broadcast.err "$TMP"/direct.out "$TMP"/direct.err; do
      if [ -f "$file" ]; then
        echo "--- $file ---" >&2
        cat "$file" >&2 || true
      fi
    done
  fi
  for pid in "${LOAD_PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
  kill ${SERVER_PID:-} ${PYTHON_PID:-} 2>/dev/null || true
  rm -rf "$TMP"
  return "$status"
}
trap cleanup EXIT

FINGERPRINT=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
FINGERPRINT_B=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
SEED=0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
KEYGEN=$(cargo run --quiet --manifest-path "$ROOT/tools/auth-keygen/Cargo.toml" -- --seed-hex "$SEED")
PUBLIC=$(printf '%s\n' "$KEYGEN" | sed -n 's/^public_key_hex=//p')
PRIVATE=$(printf '%s\n' "$KEYGEN" | sed -n 's/^private_seed_hex=//p')
test "${#PUBLIC}" -eq 64
test "$PRIVATE" = "$SEED"
printf '%s %s\n' "$FINGERPRINT" "$PUBLIC" > "$TMP/authorized_keys"
printf '%s %s\n' "$FINGERPRINT_B" "$PUBLIC" >> "$TMP/authorized_keys"

"$ROOT/target/release/ztsec-server" \
  --no-onion \
  --local-listen 127.0.0.1:4793 \
  --direct-listen 127.0.0.1:4794 \
  --direct-endpoint 127.0.0.1:4794 \
  --authorized-keys "$TMP/authorized_keys" \
  --local-socket "$TMP/telemetry.sock" \
  --control-socket "$TMP/control.sock" \
  --path /ztsec >"$TMP/server.out" 2>"$TMP/server.err" &
SERVER_PID=$!

for _ in $(seq 1 100); do
  test -S "$TMP/telemetry.sock" && test -S "$TMP/control.sock" && break
  sleep 0.1
done
test -S "$TMP/telemetry.sock"
test -S "$TMP/control.sock"

for _ in $(seq 1 100); do
  if (echo >/dev/tcp/127.0.0.1/4794) >/dev/null 2>&1; then break; fi
  sleep 0.1
done
if ! (echo >/dev/tcp/127.0.0.1/4794) >/dev/null 2>&1; then
  echo "direct listener did not become available" >&2
  cat "$TMP/server.err" >&2 || true
  exit 1
fi

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
  grep -q '\"agent_id\":' "$TMP/python.out" && break
  sleep 0.1
done
grep -q '\"agent_id\":' "$TMP/python.out"
grep -q '"CPU":"CPU"' "$TMP/python.out"

control_request_until_queued() {
  local output=$1
  shift
  for _ in $(seq 1 40); do
    if python3 "$ROOT/tools/command_client.py" --socket "$TMP/control.sock" "$@" >"$output" 2>"$output.err"; then
      if grep -q '"status": "queued"' "$output"; then
        return 0
      fi
    fi
    sleep 0.25
  done
  cat "$output" >&2 || true
  cat "$output.err" >&2 || true
  return 1
}

# Unicast relay. One authenticated agent waits for a command and acknowledges it.
ZTSEC_LOAD_ENDPOINT=ws://127.0.0.1:4793/ztsec \
ZTSEC_LOAD_CONNECTIONS=1 \
ZTSEC_LOAD_CONNECT_CONCURRENCY=1 \
ZTSEC_LOAD_WAIT_COMMAND=8 \
ZTSEC_LOAD_PRIVATE_KEY_HEX="$SEED" \
ZTSEC_LOAD_FINGERPRINT="$FINGERPRINT" \
cargo run --quiet --manifest-path "$ROOT/tools/load-test/Cargo.toml" --release >"$TMP/unicast.out" 2>"$TMP/unicast.err" &
LOAD_PIDS+=("$!")
sleep 1
control_request_until_queued "$TMP/unicast.control" --target "$FINGERPRINT" --command CMD:RECONNECT
wait "${LOAD_PIDS[-1]}"
grep -q 'successes=1 failures=0' "$TMP/unicast.out"
grep -q '"status": "queued"' "$TMP/unicast.control"

# Broadcast relay. Two authenticated agents with different identities must receive it.
ZTSEC_LOAD_ENDPOINT=ws://127.0.0.1:4793/ztsec \
ZTSEC_LOAD_CONNECTIONS=2 \
ZTSEC_LOAD_CONNECT_CONCURRENCY=2 \
ZTSEC_LOAD_WAIT_COMMAND=8 \
ZTSEC_LOAD_PRIVATE_KEY_HEX="$SEED" \
ZTSEC_LOAD_FINGERPRINTS="$FINGERPRINT,$FINGERPRINT_B" \
cargo run --quiet --manifest-path "$ROOT/tools/load-test/Cargo.toml" --release >"$TMP/broadcast.out" 2>"$TMP/broadcast.err" &
LOAD_PIDS+=("$!")
sleep 1
control_request_until_queued "$TMP/broadcast.control" --target broadcast --command CMD:RECONNECT
wait "${LOAD_PIDS[-1]}"
grep -q 'successes=2 failures=0' "$TMP/broadcast.out"
grep -q '"status": "queued"' "$TMP/broadcast.control"

# Direct transport round trip. The load client follows the relayed direct-connect
# command, authenticates on the direct listener, then returns to the primary listener
# after DIRECT_DISCONNECT.
ZTSEC_LOAD_ENDPOINT=ws://127.0.0.1:4793/ztsec \
ZTSEC_LOAD_CONNECTIONS=1 \
ZTSEC_LOAD_CONNECT_CONCURRENCY=1 \
ZTSEC_LOAD_WAIT_COMMAND=12 \
ZTSEC_LOAD_FOLLOW_DIRECT=1 \
ZTSEC_LOAD_RETURN_PRIMARY=1 \
ZTSEC_LOAD_PRIVATE_KEY_HEX="$SEED" \
ZTSEC_LOAD_FINGERPRINT="$FINGERPRINT" \
cargo run --quiet --manifest-path "$ROOT/tools/load-test/Cargo.toml" --release >"$TMP/direct.out" 2>"$TMP/direct.err" &
LOAD_PIDS+=($!)
sleep 1
control_request_until_queued "$TMP/direct-connect.control" --target "$FINGERPRINT" --command CMD:DIRECT_CONNECT:127.0.0.1:4794
for _ in $(seq 1 80); do
  grep -q 'direct transport connected' "$TMP/direct.out" && break
  sleep 0.1
done
grep -q 'direct transport connected' "$TMP/direct.out"
control_request_until_queued "$TMP/direct-disconnect.control" --target "$FINGERPRINT" --command CMD:DIRECT_DISCONNECT
wait "${LOAD_PIDS[-1]}"
grep -q 'direct transport disconnected' "$TMP/direct.out"
grep -q 'returned to primary transport' "$TMP/direct.out"
grep -q 'successes=1 failures=0' "$TMP/direct.out"

printf 'local integration: PASS\n'
