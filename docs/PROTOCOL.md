# ZTSEC transport protocol

## Scope

The agent's existing application vocabulary is retained. The transport boundary adds WebSocket framing and a versioned local IPC envelope without changing the 16 telemetry fields.

## Client authentication

```text
HELLO:FINGERPRINT:<64 lowercase/uppercase hex characters>
AUTH:CHALLENGE:<base64 32-byte nonce>
AUTH:RESPONSE:<64-hex-ed25519-public-key>:<base64 64-byte signature>
AUTH:OK
```

The signature input is domain-separated:

```text
ZTSEC-AUTH-V1\0 || fingerprint || 0x00 || nonce
```

The server compares the public key against the configured key(s) for the fingerprint and verifies the Ed25519 signature. A fresh nonce makes a captured authentication response unusable for a later challenge.

## Agent application messages

Client-to-server messages accepted after authentication:

```text
DATA:<16 fields>
HB
PONG
REQ:DATA
```

The server returns `ACK:DATA` after the telemetry message has been placed in the bounded Rust-to-Python queue. The server returns `PONG` to `HB` and to `REQ:DATA` without inventing a new telemetry payload.

For the existing agent command vocabulary, the agent continues to accept backend-originated `CMD:*` messages. The new server does not create an arbitrary remote command bus because the supplied ZIP did not contain a production server/business component to integrate; only the defined telemetry acknowledgement is implemented at the new Rust boundary.

## Telemetry schema

The original order is fixed and must remain exactly 16 fields:

```text
Country
Nickname
Tag
User
Version
Privileges
OS
GPU
CPU
RAM
AntiVirus
Uptime
AFK
Ping
HWID
Fingerprint
```

The Rust protocol crate rejects wrong field counts, oversized fields, newline/control separators, and a `Fingerprint` value that does not match the authenticated client identity.

## WebSocket constraints

The server uses a mature WebSocket implementation and caps both message and frame size at 512 KiB. Binary messages are rejected because the existing application protocol is text-oriented.

The server also applies:

* bounded authentication concurrency;
* a fixed per-connection message rate limit;
* bounded active connection permits;
* handshake/auth/idle timeouts;
* ping/pong liveness;
* a bounded downstream queue.

## Rust -> Python IPC

Rust is the Unix-domain socket listener; Python is the reconnecting client. The socket is created with mode `0660` on Unix.

Each record is:

```text
uint32_be payload_length
payload_length bytes of UTF-8 JSON
```

The JSON envelope is:

```json
{
  "protocol_version": 1,
  "message_type": "telemetry",
  "agent_id": "...",
  "fingerprint": "...",
  "timestamp_ms": 0,
  "sequence_number": 0,
  "telemetry": {
    "Country": "...",
    "Nickname": "...",
    "Tag": "...",
    "User": "...",
    "Version": "...",
    "Privileges": "...",
    "OS": "...",
    "GPU": "...",
    "CPU": "...",
    "RAM": "...",
    "AntiVirus": "...",
    "Uptime": "...",
    "AFK": "...",
    "Ping": "...",
    "HWID": "...",
    "Fingerprint": "..."
  }
}
```

The Python process must treat every field as untrusted even though the Rust process has already validated the message.

## Local control-plane relay

The Rust server exposes a separate Unix-domain control socket for the local application/operator layer. It is not reachable from the Internet and defaults to `/run/ztsec/control.sock` with mode `0660`.

Each request uses the same 4-byte big-endian length prefix as telemetry, followed by UTF-8 JSON:

```json
{
  "protocol_version": 1,
  "message_type": "agent_command",
  "request_id": "req-01",
  "target": "<64-hex-fingerprint> | broadcast",
  "command": "CMD:RECONNECT"
}
```

The server returns:

```json
{
  "protocol_version": 1,
  "message_type": "agent_command_result",
  "request_id": "req-01",
  "status": "queued",
  "target": "broadcast",
  "queued": 2,
  "dropped": 0,
  "detail": "command queued"
}
```

The authenticated control plane accepts every command family implemented by the existing agent. Commands remain bounded by the shared protocol maximums and may be unicast to one fingerprint or broadcast to a bounded number of connected agents. `CMD:DIRECT_CONNECT` is special: the operator submits it without an address; the server discovers its current public IP via ifconfig.me and constructs the concrete wire command sent to the agent.

All command families implemented by the existing agent are relayable through the authenticated private control socket. The default broadcast limit is 4096, matching the server's default authenticated connection limit, and remains configurable downward. The protocol and transport remain bounded: command/control frames have explicit size limits, broadcasts have bounded fan-out, and each agent has a bounded command queue. Direct-connect is the sole special case: the operator submits `CMD:DIRECT_CONNECT` without an address, and the server inserts its current public address discovered from ifconfig.me.

### Direct transport switch

The server-generated `CMD:DIRECT_CONNECT:<socket-address>` causes the authenticated agent to close the current WebSocket and reconnect to the built-in direct listener using a normal TCP/WebSocket connection. The connection uses the same Ed25519 authentication as the onion path.

IPv4 uses `203.0.113.10:4794`; IPv6 uses standard bracket notation such as `[2001:db8::10]:4794`.

The control plane does not accept an operator-supplied direct IP or port. `CMD:DIRECT_CONNECT` causes the Rust server to discover its current public IP through ifconfig.me and send that address with the built-in direct-listener port 4794. There is no direct-listener CLI flag. This removes the stale public-IP CLI allowlist and prevents command clients from choosing an arbitrary destination.

`CMD:DIRECT_DISCONNECT` closes the direct session and returns the agent to its original configured endpoint. The direct endpoint is not persisted to disk or added to startup arguments. The agent drops and zeroizes the runtime direct-endpoint strings on return to the configured transport. This is best-effort memory hygiene; it does not erase operating-system, shell, or audit logs.
