#!/usr/bin/env bash
set -euo pipefail
umask 077

OUT_DIR="${1:-/etc/ztsec/panel}"
SERVER_NAME="${2:-ztsec-panel}"
mkdir -p "$OUT_DIR"

openssl req -x509 -newkey rsa:4096 -nodes -days 825 \
  -subj "/CN=ZTSEC Panel CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -keyout "$OUT_DIR/ca.key" -out "$OUT_DIR/ca.crt"

openssl req -newkey rsa:3072 -nodes \
  -subj "/CN=$SERVER_NAME" \
  -keyout "$OUT_DIR/server.key" -out "$OUT_DIR/server.csr"

cat > "$OUT_DIR/server.ext" <<EXT
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:$SERVER_NAME
EXT

openssl x509 -req -days 825 -sha256 \
  -CA "$OUT_DIR/ca.crt" -CAkey "$OUT_DIR/ca.key" -CAcreateserial \
  -in "$OUT_DIR/server.csr" -out "$OUT_DIR/server.crt" -extfile "$OUT_DIR/server.ext"

python3 - "$OUT_DIR/secret" <<'PY'
import secrets
import sys
path = sys.argv[1]
with open(path, "x", encoding="ascii") as f:
    f.write(secrets.token_urlsafe(24)[:32] + "\n")
PY
chmod 600 "$OUT_DIR/secret" "$OUT_DIR/server.key" "$OUT_DIR/ca.key"
rm -f "$OUT_DIR/server.csr" "$OUT_DIR/server.ext" "$OUT_DIR/ca.srl"
printf 'Created TLS CA/server credentials and a 32-character panel secret in %s\n' "$OUT_DIR"
