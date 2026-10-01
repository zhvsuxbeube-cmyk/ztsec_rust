# Ubuntu deployment notes

Create an unprivileged service account and directories, then install the Rust binary and Python service under `/opt/ztsec`.

```bash
sudo useradd --system --home /var/lib/ztsec --shell /usr/sbin/nologin ztsec
sudo install -d -o ztsec -g ztsec -m 0750 /var/lib/ztsec /var/lib/ztsec/arti-state /var/lib/ztsec/arti-cache /etc/ztsec /opt/ztsec/bin
sudo install -o root -g ztsec -m 0640 authorized_keys /etc/ztsec/authorized_keys
sudo install -o root -g root -m 0755 target/release/ztsec-server /opt/ztsec/bin/ztsec-server
sudo install -o root -g root -m 0755 telemetry_service.py /opt/ztsec/telemetry_service.py
sudo install -o root -g root -m 0644 deploy/systemd/ztsec-server.service /etc/systemd/system/ztsec-server.service
sudo install -o root -g root -m 0644 deploy/systemd/ztsec-telemetry.service /etc/systemd/system/ztsec-telemetry.service
sudo systemctl daemon-reload
sudo systemctl enable --now ztsec-server.service ztsec-telemetry.service
```

The Rust service owns the Unix socket at `/run/ztsec/telemetry.sock`. The Python service connects to it and reconnects automatically. Do not make the socket path a public filesystem location; the sample service uses `/run/ztsec` and mode `0660`.

Use `journalctl -u ztsec-server -f` and `journalctl -u ztsec-telemetry -f` for logs. The server emits periodic connection/authentication/queue metrics at INFO without logging raw telemetry or authentication secrets.

For a public `.onion` service, the server needs outbound Tor connectivity for Arti bootstrap. The onion identity is stored under the configured state directory, so protect that directory and back it up according to the service's identity-retention policy.

## Direct listener and control socket

To expose the same authenticated WebSocket protocol on a direct IP path, the server uses its built-in direct listener on port 4794. The server discovers its current public IP automatically via ifconfig.me when a direct-connect command is requested:

```bash
./ztsec-server \
  --control-socket /run/ztsec/control.sock
```

The Rust server accepts `CMD:DIRECT_CONNECT` without an IP/port from the control plane, queries `https://ifconfig.me/ip` (with family-specific ifconfig.me fallback), combines the discovered public IP with the built-in TCP port 4794, and sends the concrete `CMD:DIRECT_CONNECT:<ip>:4794` command to the agent.

The local application/operator layer can submit an allowlisted management command with:

```bash
python3 tools/command_client.py \
  --socket /run/ztsec/control.sock \
  --target <agent-fingerprint> \
  --command CMD:RECONNECT
```

Broadcast is explicit:

```bash
python3 tools/command_client.py \
  --socket /run/ztsec/control.sock \
  --target broadcast \
  --command REQ:DATA
```

The same control interface can relay every command family supported by the existing agent protocol to either one fingerprint or `broadcast`, subject to the shared size and resource limits. This includes lifecycle, plugin load/transfer/message/event/unload, update/transfer, execute, data-request, and transport-switch commands.

Direct-switch example:

```bash
python3 tools/command_client.py \
  --socket /run/ztsec/control.sock \
  --target <agent-fingerprint> \
  --command CMD:DIRECT_CONNECT
```

Return an agent to Tor/the configured endpoint:

```bash
python3 tools/command_client.py \
  --socket /run/ztsec/control.sock \
  --target <agent-fingerprint> \
  --command CMD:DIRECT_DISCONNECT
```

The command client accepts every command family supported by the existing agent protocol; `CMD:DIRECT_CONNECT` is the only command whose destination is generated server-side. The operator never supplies a direct IP or port. The Rust server applies the same shared protocol vocabulary check, strict frame/field limits, rate limiting, bounded per-agent queues, and special server-side construction of direct-connect addresses.

The default broadcast fan-out is 4096, matching the server's default maximum authenticated connection count.

For tuning the relay resource limits without changing the protocol, the server accepts `--max-agent-command-queue`, `--max-broadcast-targets`, and `--max-control-requests-per-second`. Keep these bounded according to the host's expected agent population.
