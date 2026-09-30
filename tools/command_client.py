#!/usr/bin/env python3
"""Local ZTSEC control client for bounded, allowlisted agent-management commands."""
from __future__ import annotations

import argparse
import json
import os
import secrets
import socket
import struct
import sys
from pathlib import Path

MAX_FRAME = 64 * 1024
MAX_REQUEST_ID = 64
MAX_COMMAND = 1024


def read_exact(sock: socket.socket, size: int) -> bytes:
    out = bytearray()
    while len(out) < size:
        block = sock.recv(size - len(out))
        if not block:
            raise ConnectionError("Rust control socket disconnected")
        out.extend(block)
    return bytes(out)


def request(socket_path: Path, target: str, command: str, request_id: str | None = None) -> dict:
    request_id = request_id or secrets.token_hex(8)
    if not request_id or len(request_id.encode("utf-8")) > MAX_REQUEST_ID or not request_id.isascii() or any(ord(ch) < 33 or ord(ch) > 126 for ch in request_id):
        raise ValueError("invalid request id")
    if len(command.encode("utf-8")) > MAX_COMMAND or any(ch in command for ch in "\r\n\x00"):
        raise ValueError("invalid command length/content")
    normalized = command.strip()
    upper = normalized.upper()
    if upper in {"REQ:DATA", "CMD:RECONNECT", "CMD:CLOSE", "CMD:SLEEP", "CMD:HIBERNATE", "CMD:RESTART", "CMD:SHUTDOWN", "CMD:DIRECT_DISCONNECT"}:
        pass
    elif upper.startswith("CMD:DIRECT_CONNECT:") and normalized[len("CMD:DIRECT_CONNECT:"):].strip():
        try:
            socket_value = normalized[len("CMD:DIRECT_CONNECT:"):].strip()
            if socket_value.startswith("["):
                end = socket_value.rfind("]:" )
                if end <= 0:
                    raise ValueError
                host = socket_value[1:end]
                port = int(socket_value[end + 2:])
            else:
                host, port_text = socket_value.rsplit(":", 1)
                port = int(port_text)
            import ipaddress
            address = ipaddress.ip_address(host)
            if address.is_unspecified or address.is_multicast or not 1 <= port <= 65535:
                raise ValueError
        except (ValueError, TypeError):
            raise ValueError("invalid direct endpoint address") from None
    else:
        raise ValueError("command is not permitted by the control client")
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
    parser.add_argument("--command", required=True, help="one of the bounded management commands")
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
