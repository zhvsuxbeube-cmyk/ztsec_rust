#!/usr/bin/env python3
"""Local ZTSEC control client for the authenticated, bounded agent relay."""
from __future__ import annotations

import argparse
import json
import os
import secrets
import socket
import struct
import sys
from pathlib import Path
from typing import Final

MAX_COMMAND: Final = 3 * 1024 * 1024
MAX_FRAME: Final = MAX_COMMAND + 64 * 1024
MAX_REQUEST_ID: Final = 64

EXACT_COMMANDS: Final = {
    "REQ:DATA",
    "CMD:RECONNECT",
    "CMD:CLOSE",
    "CMD:SLEEP",
    "CMD:HIBERNATE",
    "CMD:RESTART",
    "CMD:SHUTDOWN",
    "CMD:DIRECT_CONNECT",
    "CMD:DIRECT_DISCONNECT",
}
PREFIX_COMMANDS: Final = (
    "CMD:PLUGIN:",
    "CMD:PLUGIN_BEGIN:",
    "CMD:PLUGIN_CHUNK:",
    "CMD:PLUGIN_END:",
    "CMD:PLUGIN_RESUME:",
    "CMD:PLUGIN_MSG:",
    "CMD:PLUGIN_EVENT:",
    "CMD:UNLOAD:",
    "CMD:UPDATE:",
    "CMD:UPDATE_BEGIN:",
    "CMD:UPDATE_CHUNK:",
    "CMD:UPDATE_END:",
    "CMD:EXECUTE:",
)


def is_supported_command(command: str) -> bool:
    """Mirror the shared Rust relay vocabulary; direct IPs are server-generated."""
    upper = command.upper()
    return upper in EXACT_COMMANDS or any(upper.startswith(prefix) for prefix in PREFIX_COMMANDS)


def read_exact(sock: socket.socket, size: int) -> bytes:
    out = bytearray()
    while len(out) < size:
        block = sock.recv(size - len(out))
        if not block:
            raise ConnectionError("Rust control socket disconnected")
        out.extend(block)
    return bytes(out)


def request(socket_path: Path, target: str, command: str, request_id: str | None = None) -> dict:
    if request_id is None:
        request_id = secrets.token_hex(8)
    if not request_id or len(request_id.encode("utf-8")) > MAX_REQUEST_ID or not request_id.isascii() or any(ord(ch) < 33 or ord(ch) > 126 for ch in request_id):
        raise ValueError("invalid request id")
    normalized = command.strip()
    if not normalized or len(normalized.encode("utf-8")) > MAX_COMMAND or any(ch in normalized for ch in "\r\n\x00"):
        raise ValueError("invalid command length/content")
    if not is_supported_command(normalized):
        raise ValueError("command is not supported by the ZTSEC agent protocol")
    if normalized.upper().startswith("CMD:DIRECT_CONNECT:"):
        raise ValueError("direct-connect must be requested as CMD:DIRECT_CONNECT; the server supplies its current public IP")
    if not (target.lower() == "broadcast" or (len(target) == 64 and all(ch in "0123456789abcdefABCDEF" for ch in target))):
        raise ValueError("target must be broadcast or a 64-hex agent fingerprint")

    payload = {
        "protocol_version": 1,
        "message_type": "agent_command",
        "request_id": request_id,
        "target": target,
        "command": normalized,
    }
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    if len(body) > MAX_FRAME:
        raise ValueError("control request too large")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(10.0)
        sock.connect(str(socket_path))
        sock.sendall(struct.pack("!I", len(body)) + body)
        header = read_exact(sock, 4)
        size = struct.unpack("!I", header)[0]
        if size == 0 or size > MAX_FRAME:
            raise ValueError("invalid control response size")
        response = json.loads(read_exact(sock, size).decode("utf-8"))
    if not isinstance(response, dict):
        raise ValueError("invalid control response")
    return response


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", default=os.getenv("ZTSEC_CONTROL_SOCKET", "/run/ztsec/control.sock"))
    parser.add_argument("--target", required=True, help="64-hex fingerprint or broadcast")
    parser.add_argument("--command", required=True, help="command implemented by the ZTSEC agent")
    parser.add_argument("--request-id")
    args = parser.parse_args()
    try:
        print(json.dumps(request(Path(args.socket), args.target, args.command, args.request_id), sort_keys=True))
    except (OSError, ValueError, ConnectionError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
