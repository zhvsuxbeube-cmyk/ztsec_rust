# ZTSEC agent + embedded Arti transport + Linux connection server

This repository contains the existing Windows ZTSEC agent, the supplied Arti 0.46.0 source used as an embedded client/service dependency, a Rust Linux transport boundary, and a deliberately small Python telemetry consumer.

The repository is the source of truth. The original agent application logic, 16-field telemetry schema, plugin ABI, direct-TCP update/handoff path, and existing local test utilities are retained. The new transport is selected by an explicit endpoint configuration.

## Architecture

```text
Windows endpoint
+-----------------------------------------------------------+
| ztsec_agent.exe                                           |
|                                                           |
| existing telemetry / plugin / update logic               |
|             |                                             |
|             v                                             |
| WebSocket application protocol                            |
|             |                                             |
|             v                                             |
| embedded arti-client 0.46.0                              |
|             |                                             |
|             v                                             |
| Tor network                                                |
+-------------------------.---------------------------------+
                          |
                          v
                    .onion service
                          |
                          v
+-----------------------------------------------------------+
| Ubuntu / Linux                                            |
|                                                           |
| ztsec-server (Rust / Tokio)                              |
|   - embedded Arti onion service                           |
|   - WebSocket handshake                                   |
|   - Ed25519 challenge-response auth                       |
|   - bounded parsing/rate/concurrency controls              |
|   - bounded Rust -> Python IPC queue                       |
|             |                                             |
|             | Unix domain socket                          |
|             v                                             |
| telemetry_service.py                                     |
|   - reconnecting local consumer                           |
|   - schema validation                                     |
|   - stdout processing/storage seam                         |
+-----------------------------------------------------------+
```

The application protocol remains the agent's existing `HELLO:FINGERPRINT:*`, `DATA:*`, `HB`, `PONG`, `REQ:DATA`, and `CMD:*` vocabulary. Production WebSocket messages are text frames carrying those same application messages.

`protocol`, `server`, `tools/auth-keygen`, and `tools/load-test` are members of the root Cargo workspace so clean workspace commands validate their dependency graph together.

## Repository assessment

The supplied ZIP contained two repositories:

* `ztsec_rust-main/ztsec_rust-main`: the Windows agent. It used synchronous `std::net::TcpStream`, a newline-delimited protocol, 16-field telemetry, native plugin loading, and a local update successor/handoff mechanism.
* `arti-main/arti-main`: Arti 0.46.0. Its `arti-client` crate exposes an async embedded client API, including `TorClient::create_bootstrapped` and `TorClient::connect`; the tree also contains the 0.46.0 onion-service service APIs used by the Linux server. The shipped source was copied under `vendor/arti` so the integration is reproducible against the reviewed Arti revision.

No pre-existing Rust server or Python telemetry backend was present in the supplied agent repository, so those components were added rather than replacing an existing implementation.

## Arti integration choice

The agent uses **direct embedded Arti networking** rather than spawning an Arti process or forcing the application through an externally managed SOCKS proxy. The transport module creates a bootstrapped `TorClient` once, reuses it across reconnects, and calls `tor.connect((onion_host, onion_port))` to obtain the async stream used by the existing WebSocket layer.

This keeps the user-facing deployment to one Windows executable and keeps the existing application protocol independent of whether its underlying byte stream is a direct test socket or an embedded Tor stream. The Linux server uses the supplied Arti 0.46.0 onion-service API directly as well, so the production server does not require a separate Tor/Arti executable.

Arti's onion-service support has documented limitations compared with a mature long-running C Tor deployment. The application therefore adds its own authentication, message limits, connection limits, backpressure, and failure controls, and the exact Arti version is pinned to the supplied 0.46.0 source.

## Agent build

The supplied Arti 0.46.0 source declares Rust 1.92 as its toolchain floor, and this integration pins the top-level packages to that floor as well.

### Windows x64

Use a native Windows MSVC environment:

```powershell
rustup toolchain install 1.92.0-x86_64-pc-windows-msvc
rustup default 1.92.0-x86_64-pc-windows-msvc
cargo test --package ztsec_agent --tests
cargo build --release --target x86_64-pc-windows-msvc --bin ztsec_agent
```

Result:

```text
target\x86_64-pc-windows-msvc\release\ztsec_agent.exe
```

The final Windows executable embeds Arti; no separate Arti executable is required.

### Linux server

```bash
rustup toolchain install 1.92.0-x86_64-unknown-linux-gnu
rustup default 1.92.0-x86_64-unknown-linux-gnu
cargo test --workspace --all-targets
cargo build --release --package ztsec_server --bin ztsec-server
```

Result:

```text
target/release/ztsec-server
```

### Python

The telemetry service uses only Python standard-library modules:

```bash
python3 -m py_compile telemetry_service.py python_service.py tools/panel.py tools/test_update_contract.py tools/test_python_service.py
python3 -m unittest tools.test_python_service
python3 tools/test_update_contract.py
```

## Docker build

`docker/rust-server-builder.Dockerfile` is a reproducible Linux build environment based on a pinned Rust 1.92 image. It uses BuildKit cache mounts for Cargo registry/git/target data and copies the Arti source before the application to maximize dependency caching.

Example:

```bash
docker build -f docker/rust-server-builder.Dockerfile --output type=local,dest=dist .
```

Docker is a build aid; the final deployment artifact remains the standalone `ztsec-server` Linux executable.

## Agent configuration

The old direct-TCP configuration remains available for existing local tests:

```powershell
ztsec_agent.exe --ip 127.0.0.1 --port 4793
```

The production transport is selected with:

```powershell
$env:ZTSEC_ENDPOINT = 'ws://<56-char-v3-address>.onion:443/ztsec'
$env:ZTSEC_AUTH_KEY_FILE = 'C:\ProgramData\ZTSEC\agent.key'
$env:ZTSEC_ARTI_STATE_DIR = 'C:\ProgramData\ZTSEC\arti-state'
$env:ZTSEC_ARTI_CACHE_DIR = 'C:\ProgramData\ZTSEC\arti-cache'
.\ztsec_agent.exe --heartbeat 30 --connect-timeout 15 --handshake-timeout 10 --retry-base 1 --retry-max 60
```

The `--endpoint`, `--auth-key-file`, `--arti-state-dir`, and `--arti-cache-dir` command-line forms are also supported. Endpoint parsing rejects DNS-based onion lookup: a `.onion` endpoint must be a valid v3 hostname, and the code passes that hostname directly to Arti.

For an identity bootstrap/debug value, the agent can print its existing telemetry fingerprint without opening a network connection:

```powershell
ztsec_agent.exe --print-fingerprint
```

The agent private key file accepts either exactly 32 raw seed bytes or 64 hexadecimal characters. Keep this file private and ACL it so only the agent account can read it.

## Authentication

The application layer uses Ed25519 challenge-response:

```text
client -> HELLO:FINGERPRINT:<64-hex>
server -> AUTH:CHALLENGE:<base64 32-byte nonce>
client -> AUTH:RESPONSE:<public-key-hex>:<base64 signature>
server -> AUTH:OK
```

The signature covers a domain-separated message containing the fingerprint and fresh nonce. The server's `authorized_keys` file maps the fingerprint to one or more public keys so that a new key can be added before the old key is removed.

Generate a development key with the helper package:

```bash
cargo run --manifest-path tools/auth-keygen/Cargo.toml --release
```

The helper prints a private seed and public key. Never put the private seed on the server.

Server key file format:

```text
# fingerprint public_key_hex
<agent-fingerprint> <64-hex-ed25519-public-key>
```

Authentication failures are rejected before telemetry processing and are subject to the auth semaphore and timeout controls.

## Rust server deployment

The server binds its onion service on the configured virtual port (default `443`) and WebSocket path (default `/ztsec`). It can optionally expose a loopback-only WebSocket listener for deterministic tests.

Example production invocation:

```bash
./ztsec-server \
  --authorized-keys /etc/ztsec/authorized_keys \
  --state-dir /var/lib/ztsec/arti-state \
  --cache-dir /var/lib/ztsec/arti-cache \
  --local-socket /run/ztsec/telemetry.sock \
  --path /ztsec \
  --onion-port 443 \
  --max-connections 4096 \
  --max-auth-inflight 64 \
  --ipc-queue 256 \
  --message-rate 10 \
  --handshake-timeout 8 \
  --auth-timeout 8 \
  --idle-timeout 90 \
  --ping-interval 30
```

For deterministic local tests, disable Arti and bind a loopback WebSocket listener:

```bash
./ztsec-server \
  --no-onion \
  --local-listen 127.0.0.1:4793 \
  --authorized-keys /tmp/ztsec-authorized_keys \
  --local-socket /tmp/ztsec-telemetry.sock
```

The local listener is intentionally a test facility, not the production public endpoint.

## Python telemetry service

The Rust process owns the Unix domain socket and accepts one local telemetry consumer connection at a time. The Python process connects to that socket and automatically reconnects when Rust restarts.

```bash
export ZTSEC_IPC_SOCKET=/run/ztsec/telemetry.sock
python3 telemetry_service.py
```

Each Rust -> Python message is:

```text
4-byte big-endian payload length
JSON envelope
```

The envelope contains protocol version, message type, agent ID/fingerprint, timestamps, a sequence number, and the original structured 16-field telemetry object.

The bounded Rust queue is deliberately finite. If Python is unavailable or too slow, the queue fills and additional telemetry is dropped rather than growing without limit. The network service remains responsive to unrelated clients.

The `process()` function is the application/storage seam; it currently emits compact JSON to stdout because the supplied ZIP did not contain an existing storage backend.

## Protocol boundary

The original telemetry fields are preserved exactly:

```text
Country | Nickname | Tag | User | Version | Privileges | OS | GPU |
CPU | RAM | AntiVirus | Uptime | AFK | Ping | HWID | Fingerprint
```

The Rust protocol crate validates field count, maximum field size, forbidden separators/control characters, and fingerprint consistency before handing the object to Python.

The Rust transport accepts these client-originated application messages:

```text
HELLO:FINGERPRINT:<fingerprint>
DATA:<16 fields>
HB
PONG
REQ:DATA
CMD:*   (agent-side command vocabulary is preserved for the existing agent)
```

The new server currently generates the telemetry acknowledgement `ACK:DATA` itself. The ZIP did not contain a pre-existing production server/business layer for remote command delivery, so the new Rust/Python boundary intentionally does not invent a separate command-control application. The existing legacy direct-TCP path remains available for local compatibility and for the original plugin/update command behavior.

## Resource controls

Default transport limits are intentionally conservative and configurable:

* 4096 simultaneous authenticated/active connection permits.
* 64 authentication operations in flight.
* 512 KiB maximum WebSocket message/frame size.
* 256-entry bounded Rust -> Python queue.
* 10 application messages/second per connection.
* 8-second WebSocket/auth timeouts.
* 90-second idle timeout with 30-second server pings.
* Arti onion-service rate limiting at introduction points and a circuit stream cap.
* Plugin chunks remain bounded at 128 KiB and the existing 256 MiB plugin transfer cap is preserved.
* Windows updates retain the original 64 MiB logical cap; production WebSocket updates use `UPDATE_BEGIN`, `UPDATE_CHUNK`, and `UPDATE_END` so a large executable is never held in one WebSocket message.

The server uses one Tokio runtime and a bounded task-per-admitted-connection model rather than OS threads per client. Synchronous file/update operations in the agent's WebSocket command path are moved into `spawn_blocking` workers.

## Reconnect/failure behavior

The Windows agent uses bounded exponential reconnect backoff with jitter. Arti bootstrap is cached in the connector and retried through the same bounded loop when the Tor path is unavailable.

The server rejects wrong WebSocket paths, invalid auth, invalid protocol versions/fields, oversized messages, binary frames, rate-limit violations, and unexpected application messages cleanly.

The Python service retries Rust IPC with an exponential delay capped at ten seconds. A Python restart does not require Rust to restart.

## Testing

Deterministic tests:

```bash
cargo test --workspace --all-targets
python3 -m unittest tools.test_python_service
python3 tools/test_update_contract.py
```

The supplied Windows tests for plugin loading, execute, and update handoff remain in the tree. The existing `tools/panel.py`, `tools/exec_test.py`, and `tools/panel_test.py` remain available for Windows functional testing.

### Local WebSocket integration

Build the Linux server and run it with `--no-onion --local-listen 127.0.0.1:4793`. Run `python3 telemetry_service.py` against its Unix socket. Then point a test agent at:

```text
ws://127.0.0.1:4793/ztsec
```

The local path exercises the same WebSocket/auth/validation/IPC boundary without depending on the public Tor network.

### Optional Tor end-to-end

A real `.onion` end-to-end test requires a live Tor-capable environment. It should be run separately from deterministic CI so an external network failure cannot create a false negative in the protocol test suite.

## Load testing

The load-test tool is intentionally a separate package so its test credentials are never part of the server release binary:

```bash
export ZTSEC_LOAD_ENDPOINT=ws://127.0.0.1:4793/ztsec
export ZTSEC_LOAD_CONNECTIONS=1000
export ZTSEC_LOAD_DURATION_SECS=30
export ZTSEC_LOAD_CONNECT_CONCURRENCY=256
export ZTSEC_LOAD_PRIVATE_KEY_HEX='<32-byte-test-seed-as-64-hex-chars>'
export ZTSEC_LOAD_FINGERPRINT='<64-hex-test-fingerprint>'
cargo run --manifest-path tools/load-test/Cargo.toml --release
```

The tool measures connection establishment count/rate and sustained periodic telemetry success/failure. Run it alongside `pidstat`, `ps`, or cgroup metrics to record actual CPU and RSS. No capacity number is claimed by this repository until a specified machine/configuration has been measured.

Recommended scenarios are idle connections, periodic telemetry, bursts, slow Python IPC consumption, Python restart, Rust restart, reconnect storms, and malformed/oversized clients.

## CI

`.github/workflows/build.yml` contains separate Linux and Windows jobs, Python validation, workspace tests, the existing Windows plugin/execute/update tests, Docker build validation, and artifact packaging. Cargo cache directories use `actions/cache@v4`; Docker uses BuildKit cache mounts.

The GitHub workflow intentionally does not make a live external Tor service a required gate.

## Deployment services

Example systemd units are under `deploy/systemd/`:

* `ztsec-server.service`
* `ztsec-telemetry.service`

The server owns `/run/ztsec/telemetry.sock`, and the Python service connects to it. The units use an ordinary unprivileged `ztsec` user/group, restart policies, a high-but-bounded file descriptor limit, and private temporary directories.

Create the deployment directories and key file with restrictive permissions. The Arti state/cache directories should also be writable only by the service account.

## Security notes

Tor supplies reachability/privacy properties for the onion path; it does not decide whether a client is an authorized ZTSEC agent. Authorization is application-level Ed25519 challenge-response.

No production private keys or credentials are embedded. Tests use deterministic in-process signing keys only inside test code. The load-test package requires its private seed from the environment.

The Python process has no Internet-facing listener and uses only a Unix-domain socket. The Rust process does not expose raw telemetry to the Python process until validation succeeds.

No new `unsafe` code was introduced in the transport/server path. Existing platform-specific `unsafe` code in the supplied update/syscall implementation was preserved rather than rewritten.

## Compatibility / migration

```text
OLD
  ztsec_agent --ip 127.0.0.1 --port 4793
  synchronous TCP + newline protocol

NEW
  ZTSEC_ENDPOINT=ws://<v3-onion>:443/ztsec
  Ed25519 application auth
  embedded Arti stream -> WebSocket text frames

REASON
  introduce the requested onion transport without changing the telemetry schema
  or requiring a separate Arti executable.

MIGRATION
  provision an agent signing key, register its public key against the agent's
  existing telemetry fingerprint, set ZTSEC_ENDPOINT and ZTSEC_AUTH_KEY_FILE,
  and deploy the Rust server + Python service on Ubuntu.
```

## Known limitations

1. Rust/Cargo, Docker, and a Windows MSVC Rust toolchain were not installed in the execution environment used to modify this repository, so release compilation could not be performed here.
2. A live Tor/onion end-to-end test could not be truthfully run in this environment. The project therefore separates deterministic local WebSocket/protocol tests from optional live Tor verification.
3. The supplied Arti version is 0.46.0. Its onion-service implementation has documented limitations compared with a mature separately managed C Tor deployment; review the 0.46.0 Arti documentation/source before production threat-model sign-off.
4. The ZIP did not contain a pre-existing production server-side command/business layer, so the new Rust/Python IPC boundary focuses on validated telemetry ingest plus the acknowledgement required by the existing agent/update readiness flow. The original legacy direct-TCP command path is retained for compatibility testing.
5. A root `Cargo.lock` could not be generated in this environment because Cargo is unavailable. The release CI is responsible for lockfile generation/verification before building; the vendored Arti source itself includes its reviewed 0.46.0 lockfile.

## CI compiler logs

The Linux and Windows CI jobs run `cargo check --workspace --all-targets` before lockfile generation, tests, or release builds. Complete stdout/stderr is captured to `linux_log.log` and `windows_log.log` respectively. The logs are uploaded as dedicated artifacts on every runner outcome and are included in the final release bundle when both platform jobs succeed.
