# External Panel Gateway

The ZTSEC relay now has an optional external panel gateway. It is disabled unless `--panel-listen` is supplied.

## Security model

The gateway is a dedicated TLS TCP listener and does not expose `/run/ztsec/control.sock` or the agent WebSocket directly.

Authentication uses a 32-character high-entropy ASCII secret stored locally at both ends. The secret is **never transmitted**. The relay creates a fresh 32-byte random challenge for every authentication exchange and the panel returns:

```text
HMAC-SHA256(
  secret,
  "ZTSEC-PANEL-AUTH-V1\\0" || panel_id || "\\0" || challenge
)
```

The Rust verifier uses HMAC verification rather than comparing the secret itself. TLS is mandatory and the Python client verifies the relay certificate against the supplied CA/certificate; it does not allow insecure certificate bypasses.

The relay keeps the loaded secret in zeroizing memory and, on Unix, rejects a secret file that has any group/other permission bits set. The helper creates the secret with mode `0600`.

## Wire framing

After TLS is established, messages use:

```text
4-byte big-endian payload length
JSON UTF-8 payload
```

The maximum frame is 64 KiB.

Authentication messages are:

```json
{"protocol_version":1,"message_type":"panel_hello","panel_id":"panel-01"}
```

```json
{"protocol_version":1,"message_type":"panel_challenge","panel_id":"panel-01","challenge":"...","expires_at_ms":123}
```

```json
{"protocol_version":1,"message_type":"panel_proof","panel_id":"panel-01","proof":"..."}
```

Successful authentication returns:

```json
{"protocol_version":1,"message_type":"panel_authenticated","expires_at_ms":123}
```

After authentication, the gateway streams current telemetry snapshots followed by live telemetry updates. A lightweight `panel_ping` / `panel_pong` keeps the session active.

## Scope

The public gateway is deliberately telemetry/status only. It does not accept `agent_command` requests or expose the agent's existing execution, plugin, update, lifecycle, or transport-switching control vocabulary on the Internet. Those capabilities remain behind the private Unix control socket.

For privileged command operations from an external administrative workstation, use an authenticated administrative tunnel to `/run/ztsec/control.sock` rather than publishing the command surface as a public TCP service.
