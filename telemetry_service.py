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
    value = json.loads(payload.decode("utf-8"))
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
                    message = receive_frame(sock)
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
