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
