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

The maximum frame matches the authenticated control-plane limit (3 MiB command payload plus 64 KiB framing headroom), so the panel does not impose a smaller cap than the existing command relay.

Command requests use the same shape as the private control socket:

```json
{"protocol_version":1,"message_type":"agent_command","request_id":"req-01","target":"<64-hex-fingerprint-or-broadcast>","command":"CMD:RECONNECT"}
```

A successful routing response is the shared `agent_command_result` object.

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

After authentication, the gateway streams current telemetry snapshots followed by live telemetry updates. The same authenticated session also accepts `agent_command` messages and returns the shared `agent_command_result` response. Commands go through the exact same protocol validation, target validation, direct-connect materialization, bounded queueing, broadcast limit, and per-connection rate limiting used by the private control plane. A lightweight `panel_ping` / `panel_pong` keeps the session active.

## Scope

The optional gateway is a remote administrative surface, not an unauthenticated shell. After successful TLS plus challenge/response authentication, it exposes the same bounded command vocabulary already implemented by the agent: lifecycle, plugin load/transfer/event/unload, update/transfer, execute, telemetry request, and transport switching. `CMD:DIRECT_CONNECT` remains server-generated: panels may request the abstract command, but they cannot inject an IP or port.

The gateway is disabled by default. Keep the listener behind an appropriate network boundary, protect the panel secret like a credential, and rely on the same rate limits and bounded queues as the private control socket.
