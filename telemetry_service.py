#!/usr/bin/env python3
"""Local ZTSEC telemetry consumer; intentionally has no Internet-facing listener."""
from __future__ import annotations

import json
import logging
import os
import socket
import struct
import sys
import time
from pathlib import Path
from typing import Any

MAX_FRAME = 256 * 1024
MAX_FIELD = 64 * 1024
RETRY_MAX = 10.0

LOGGER = logging.getLogger("ztsec-telemetry")


MAX_CONTROL_COMMAND = 3 * 1024 * 1024
MAX_CONTROL_FRAME = MAX_CONTROL_COMMAND + 64 * 1024

def is_supported_command(command: str) -> bool:
    upper = command.upper()
    exact = {
        "REQ:DATA", "CMD:RECONNECT", "CMD:CLOSE", "CMD:SLEEP",
        "CMD:HIBERNATE", "CMD:RESTART", "CMD:SHUTDOWN",
        "CMD:DIRECT_CONNECT", "CMD:DIRECT_DISCONNECT",
    }
    prefixes = (
        "CMD:PLUGIN:", "CMD:PLUGIN_BEGIN:", "CMD:PLUGIN_CHUNK:",
        "CMD:PLUGIN_END:", "CMD:PLUGIN_RESUME:", "CMD:PLUGIN_MSG:",
        "CMD:PLUGIN_EVENT:", "CMD:UNLOAD:", "CMD:UPDATE:",
        "CMD:UPDATE_BEGIN:", "CMD:UPDATE_CHUNK:", "CMD:UPDATE_END:",
        "CMD:EXECUTE:",
    )
    return upper in exact or any(upper.startswith(prefix) for prefix in prefixes)


def send_agent_command(socket_path: Path, target: str, command: str, request_id: str) -> dict[str, Any]:
    """Send one bounded control request over the private Unix socket."""
    if not request_id or len(request_id.encode("utf-8")) > 64 or not request_id.isascii() or any(ord(ch) < 33 or ord(ch) > 126 for ch in request_id):
        raise ValueError("invalid request id")
    if not (target.lower() == "broadcast" or (len(target) == 64 and all(ch in "0123456789abcdefABCDEF" for ch in target))):
        raise ValueError("target must be broadcast or a 64-hex agent fingerprint")
    if not command or len(command.encode("utf-8")) > MAX_CONTROL_COMMAND or any(ch in command for ch in "\r\n\x00"):
        raise ValueError("invalid command")
    normalized = command.strip()
    if not is_supported_command(normalized):
        raise ValueError("command is not permitted by the control plane")
    if normalized.upper().startswith("CMD:DIRECT_CONNECT:"):
        raise ValueError("direct-connect must be requested without an address; the server supplies its public IP")

    request = {
        "protocol_version": 1,
        "message_type": "agent_command",
        "request_id": request_id,
        "target": target,
        "command": normalized,
    }
    payload = json.dumps(request, separators=(",", ":")).encode("utf-8")
    if len(payload) > MAX_CONTROL_FRAME:
        raise ValueError("control request too large")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(10.0)
        sock.connect(str(socket_path))
        sock.sendall(struct.pack("!I", len(payload)) + payload)
        response = receive_frame_from_control(sock)
    return response


def receive_frame_from_control(sock: socket.socket) -> dict[str, Any]:
    header = read_exact(sock, 4)
    size = struct.unpack("!I", header)[0]
    if size == 0 or size > MAX_CONTROL_FRAME:
        raise ValueError(f"invalid control response size: {size}")
    value = json.loads(read_exact(sock, size).decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("control response must be an object")
    return value

def read_exact(sock: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        block = sock.recv(remaining)
        if not block:
            raise ConnectionError("Rust IPC peer disconnected")
        chunks.append(block)
        remaining -= len(block)
    return b"".join(chunks)


def receive_frame(sock: socket.socket) -> dict[str, Any] | None:
    header = read_exact(sock, 4)
    size = struct.unpack("!I", header)[0]
    if size == 0 or size > MAX_FRAME:
        raise ValueError(f"invalid IPC frame size: {size}")
    payload = read_exact(sock, size)
    if not payload:
        raise ValueError("empty IPC payload")
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError(f"invalid IPC JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError("IPC payload must be an object")
    return value


def validate_telemetry(message: dict[str, Any]) -> dict[str, str]:
    if message.get("protocol_version") != 1 or message.get("message_type") != "telemetry":
        raise ValueError("unsupported IPC protocol message")
    for key in ("agent_id", "fingerprint"):
        value = message.get(key)
        if not isinstance(value, str) or not value or len(value) > 128:
            raise ValueError(f"invalid {key}")
    telemetry = message.get("telemetry")
    if not isinstance(telemetry, dict):
        raise ValueError("telemetry must be an object")
    expected = [
        "Country", "Nickname", "Tag", "User", "Version", "Privileges", "OS",
        "GPU", "CPU", "RAM", "AntiVirus", "Uptime", "AFK", "Ping", "HWID", "Fingerprint",
    ]
    output: dict[str, str] = {}
    for key in expected:
        value = telemetry.get(key)
        if not isinstance(value, str):
            raise ValueError(f"telemetry field {key} must be a string")
        if len(value.encode("utf-8")) > MAX_FIELD or any(ch in value for ch in "\r\n|"):
            raise ValueError(f"telemetry field {key} is invalid")
        output[key] = value
    fingerprint = message["fingerprint"]
    if len(fingerprint) != 64 or any(ch not in "0123456789abcdefABCDEF" for ch in fingerprint):
        raise ValueError("invalid fingerprint")
    if output["Fingerprint"] != fingerprint:
        raise ValueError("telemetry fingerprint mismatch")
    for key in ("timestamp_ms", "sequence_number"):
        value = message.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError(f"invalid {key}")
    return output


def process(message: dict[str, Any]) -> None:
    telemetry = validate_telemetry(message)
    record = {
        "agent_id": message["agent_id"],
        "fingerprint": message["fingerprint"],
        "timestamp_ms": message.get("timestamp_ms"),
        "sequence_number": message.get("sequence_number"),
        "telemetry": telemetry,
    }
    # Stdout is the current application sink; no storage backend existed in the supplied ZIP.
    print(json.dumps(record, separators=(",", ":"), sort_keys=True), flush=True)


def serve(socket_path: Path) -> None:
    delay = 1.0
    while True:
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.connect(str(socket_path))
                LOGGER.info("connected to Rust IPC at %s", socket_path)
                delay = 1.0
                while True:
                    try:
                        message = receive_frame(sock)
                    except (ValueError, UnicodeError, json.JSONDecodeError, RecursionError) as exc:
                        LOGGER.warning("discarding malformed telemetry frame: %s", exc)
                        continue
                    if message is None:
                        return
                    try:
                        process(message)
                    except (ValueError, UnicodeError, json.JSONDecodeError, RecursionError) as exc:
                        LOGGER.warning("discarding malformed telemetry frame: %s", exc)
        except (OSError, ConnectionError) as exc:
            LOGGER.warning("Rust IPC unavailable: %s; reconnecting", exc)
            time.sleep(delay)
            delay = min(RETRY_MAX, delay * 2.0)


def main() -> int:
    logging.basicConfig(
        level=os.getenv("ZTSEC_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    path = Path(os.getenv("ZTSEC_IPC_SOCKET", "/run/ztsec/telemetry.sock"))
    try:
        serve(path)
    except KeyboardInterrupt:
        LOGGER.info("shutdown requested")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
