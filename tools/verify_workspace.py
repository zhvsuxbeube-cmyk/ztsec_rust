#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
manifest = ROOT / "Cargo.toml"
text = manifest.read_text(encoding="utf-8")
match = re.search(r"(?ms)^\[workspace\]\s*(.*?)(?=^\[|\Z)", text)
if not match:
    raise SystemExit("missing [workspace] section")
section = match.group(1)
if 'exclude = ["vendor/arti"]' not in section:
    raise SystemExit("vendor/arti is not explicitly excluded from the ZTSEC workspace")
members = re.search(r"(?ms)^members\s*=\s*\[(.*?)\]", section)
if members and "vendor/arti" in members.group(1):
    raise SystemExit("vendor/arti must not be listed as a workspace member")
server_manifest = ROOT / "server" / "Cargo.toml"
server_text = server_manifest.read_text(encoding="utf-8")
if '[[' + 'bin]]' not in server_text:
    raise SystemExit("server/Cargo.toml must explicitly declare the ztsec-server binary target")
bin_match = re.search(r'(?ms)^\[\[bin\]\]\s*name\s*=\s*"([^"]+)"\s*path\s*=\s*"([^"]+)"', server_text)
if not bin_match or bin_match.group(1) != "ztsec-server" or bin_match.group(2) != "src/main.rs":
    raise SystemExit("server/Cargo.toml binary target must be ztsec-server from src/main.rs")
print("OK: vendor/arti is excluded and ztsec-server is the explicit Linux binary target")
dockerfile = ROOT / "docker" / "rust-server-builder.Dockerfile"
docker_text = dockerfile.read_text(encoding="utf-8")
import re as _re
lock_match = _re.search(r"(?m)^\s+cargo generate-lockfile\s*$", docker_text)
if not lock_match:
    raise SystemExit("Dockerfile must contain a cargo generate-lockfile step")
lock_step = lock_match.start()
required_target_markers = [
    "printf 'fn main() {}\\n' > src/main.rs",
    "printf 'fn main() {}\\n' > server/src/main.rs",
    "printf 'pub fn docker_lockfile_stub() {}\\n' > server/src/lib.rs",
    "printf 'pub fn docker_lockfile_stub() {}\\n' > protocol/src/lib.rs",
    "printf 'fn main() {}\\n' > tools/auth-keygen/src/main.rs",
    "printf 'fn main() {}\\n' > tools/load-test/src/main.rs",
]
for marker in required_target_markers:
    pos = docker_text.find(marker)
    if pos < 0 or pos > lock_step:
        raise SystemExit(f"Dockerfile must seed workspace target before cargo generate-lockfile: {marker}")
print("OK: Docker lockfile stage seeds every ZTSEC workspace package target")
required_manifest_markers = [
    "COPY protocol/Cargo.toml ./protocol/Cargo.toml",
    "COPY server/Cargo.toml ./server/Cargo.toml",
    "COPY tools/auth-keygen/Cargo.toml ./tools/auth-keygen/Cargo.toml",
    "COPY tools/load-test/Cargo.toml ./tools/load-test/Cargo.toml",
]
for marker in required_manifest_markers:
    pos = docker_text.find(marker)
    if pos < 0 or pos > lock_step:
        raise SystemExit(f"Dockerfile must copy workspace member manifest before cargo generate-lockfile: {marker}")
print("OK: Docker lockfile stage copies every ZTSEC workspace package manifest")


def verify_docker_artifact_copy() -> None:
    dockerfile = (ROOT / "docker" / "rust-server-builder.Dockerfile").read_text(encoding="utf-8")
    build_pos = dockerfile.find("cargo build --release --package ztsec_server --bin ztsec-server")
    if build_pos < 0:
        raise SystemExit("Dockerfile missing release server build")
    # The target directory is a BuildKit cache mount. The binary must be copied
    # to a normal image-layer path while that mount is active.
    copy_pos = dockerfile.find("cp target/release/ztsec-server /out/ztsec-server", build_pos)
    if copy_pos < 0:
        raise SystemExit("Dockerfile must copy ztsec-server to /out in the build RUN")
    next_run = dockerfile.find("\nRUN ", build_pos + 1)
    if next_run >= 0 and copy_pos > next_run:
        raise SystemExit("Dockerfile copies the cached target binary in a later RUN layer")
    if "test -s target/release/ztsec-server" not in dockerfile:
        raise SystemExit("Dockerfile must verify the built Linux server binary")
    if "test -s /out/ztsec-server" not in dockerfile:
        raise SystemExit("Dockerfile must verify the exported Linux server binary")
    workflow = (ROOT / ".github" / "workflows" / "build.yml").read_text(encoding="utf-8")
    if "docker create ztsec-rust-builder /ztsec-server" not in workflow:
        raise SystemExit("Docker artifact extraction must provide /ztsec-server because the scratch image has no default command")
    if "docker create ztsec-rust-builder)" in workflow:
        raise SystemExit("Docker artifact extraction must not call docker create without a command")
    print("OK: Docker copies ztsec-server from the target cache within the build RUN")

verify_docker_artifact_copy()

def verify_relay_controls() -> None:
    server = (ROOT / "server" / "src" / "lib.rs").read_text(encoding="utf-8")
    agent = (ROOT / "src" / "net.rs").read_text(encoding="utf-8")
    transport = (ROOT / "src" / "transport.rs").read_text(encoding="utf-8")
    for marker in (
        "RateLimiter::new(server.config.max_control_requests_per_second)",
        "CMD:DIRECT_CONNECT:",
        "CMD:DIRECT_DISCONNECT",
        "CMD:RECONNECT",
        "CMD:CLOSE",
        "CMD:SLEEP",
        "CMD:HIBERNATE",
        "CMD:RESTART",
        "CMD:SHUTDOWN",
        "REQ:DATA",
    ):
        if marker not in server:
            raise SystemExit(f"server relay control marker missing: {marker}")
    if "fn parse_direct_command(raw: &str, endpoint_path: &str)" not in agent or "CommandResult::SwitchDirect(endpoint)" not in agent:
        raise SystemExit("agent direct-connect command must switch transport immediately")
    if "let _ = session.close().await;" not in agent:
        raise SystemExit("agent transport switches must close the current session")
    for marker in (
        "active_endpoint = primary_endpoint.clone();",
        "connector.set_endpoint(primary_endpoint.clone());",
        "direct_override = false;",
        "Zeroizing::new(connector.endpoint().target().0.to_owned())",
    ):
        if marker not in agent:
            raise SystemExit(f"agent direct-address cleanup marker missing: {marker}")
    if "impl Drop for Endpoint" not in transport or "host.zeroize()" not in transport:
        raise SystemExit("direct endpoint memory zeroization guard missing")
    if "fn format_authority(host: &str, port: u16) -> String" not in transport:
        raise SystemExit("WebSocket authority formatter missing for IPv6 direct endpoints")
    command_client = (ROOT / "tools" / "command_client.py").read_text(encoding="utf-8")
    for command in ("CMD:RECONNECT", "CMD:CLOSE", "CMD:SLEEP", "CMD:HIBERNATE", "CMD:RESTART", "CMD:SHUTDOWN", "CMD:DIRECT_CONNECT:", "CMD:DIRECT_DISCONNECT"):
        if command not in command_client:
            raise SystemExit(f"control command client relay vocabulary is incomplete: {command}")
    print("OK: management relay, direct-switch, and IPv6 transport guards present")


verify_relay_controls()
