#!/usr/bin/env python3
import json
import struct
import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import telemetry_service as python_service  # noqa: E402


def telemetry_message():
    fingerprint = "a" * 64
    fields = [
        "Local", "host", "ZTSecurity", "user", "Rust-Native/1", "User", "Windows",
        "GPU", "CPU", "8/16 GB", "AV", "1h", "0m", "1 ms", "hwid", fingerprint,
    ]
    return {
        "protocol_version": 1,
        "message_type": "telemetry",
        "agent_id": fingerprint,
        "fingerprint": fingerprint,
        "timestamp_ms": 1,
        "sequence_number": 1,
        "telemetry": dict(zip([
            "Country", "Nickname", "Tag", "User", "Version", "Privileges", "OS",
            "GPU", "CPU", "RAM", "AntiVirus", "Uptime", "AFK", "Ping", "HWID", "Fingerprint",
        ], fields)),
    }


class TestPythonService(unittest.TestCase):
    def test_roundtrip_frame_over_socketpair(self):
        left, right = python_service.socket.socketpair()
        try:
            payload = json.dumps(telemetry_message(), separators=(",", ":")).encode()
            right.sendall(struct.pack("!I", len(payload)) + payload)
            message = python_service.receive_frame(left)
            self.assertEqual(python_service.validate_telemetry(message)["Fingerprint"], "a" * 64)
        finally:
            left.close()
            right.close()

    def test_rejects_oversized_frame_without_allocating_payload(self):
        left, right = python_service.socket.socketpair()
        try:
            right.sendall(struct.pack("!I", python_service.MAX_FRAME + 1))
            with self.assertRaises(ValueError):
                python_service.receive_frame(left)
        finally:
            left.close()
            right.close()

    def test_rejects_fingerprint_mismatch(self):
        message = telemetry_message()
        message["telemetry"]["Fingerprint"] = "b" * 64
        with self.assertRaises(ValueError):
            python_service.validate_telemetry(message)


if __name__ == "__main__":
    unittest.main()
