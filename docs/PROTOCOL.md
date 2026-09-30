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
