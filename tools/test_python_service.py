#!/usr/bin/env python3
import json
import struct
import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))
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


class TestControlClient(unittest.TestCase):
    def test_rejects_unbounded_remote_commands(self):
        import command_client
        with self.assertRaises(ValueError):
            command_client.request(Path("/does/not/exist"), "a" * 64, "CMD:EXECUTE:ps1:ZmFrZQ==")

    def test_rejects_invalid_target(self):
        import command_client
        with self.assertRaises(ValueError):
            command_client.request(Path("/does/not/exist"), "not-an-agent", "CMD:RECONNECT")

    def test_accepts_direct_management_command_shape(self):
        import command_client
        with self.assertRaises(OSError):
            command_client.request(Path("/does/not/exist"), "a" * 64, "cmd:direct_connect:203.0.113.10:4794")

    def test_accepts_power_management_command_shape(self):
        import command_client
        with self.assertRaises(OSError):
            command_client.request(Path("/does/not/exist"), "a" * 64, "CMD:SHUTDOWN")

    def test_rejects_unusable_direct_address(self):
        import command_client
        with self.assertRaises(ValueError):
            command_client.request(Path("/does/not/exist"), "a" * 64, "CMD:DIRECT_CONNECT:0.0.0.0:4794")
        with self.assertRaises(ValueError):
            command_client.request(Path("/does/not/exist"), "a" * 64, "CMD:DIRECT_CONNECT:239.1.1.1:4794")


class TestControlSocket(unittest.TestCase):
    def test_send_agent_command_roundtrip(self):
        import socket as sock_mod
        import tempfile
        import threading
        import telemetry_service

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "control.sock"
            listener = sock_mod.socket(sock_mod.AF_UNIX, sock_mod.SOCK_STREAM)
            listener.bind(str(path))
            listener.listen(1)

            def server_once():
                conn, _ = listener.accept()
                try:
                    header = conn.recv(4)
                    size = struct.unpack("!I", header)[0]
                    body = json.loads(python_service.read_exact(conn, size).decode())
                    self.assertEqual(body["message_type"], "agent_command")
                    response = {"protocol_version": 1, "message_type": "agent_command_result", "request_id": body["request_id"], "status": "queued", "target": body["target"], "queued": 1, "dropped": 0, "detail": "command queued"}
                    payload = json.dumps(response, separators=(",", ":")).encode()
                    conn.sendall(struct.pack("!I", len(payload)) + payload)
                finally:
                    conn.close()
                    listener.close()

            thread = threading.Thread(target=server_once, daemon=True)
            thread.start()
            response = telemetry_service.send_agent_command(path, "a" * 64, "CMD:RECONNECT", "req-1")
            thread.join(2)
            self.assertEqual(response["status"], "queued")

    def test_send_agent_command_rejects_execute(self):
        import telemetry_service
        with self.assertRaises(ValueError):
            telemetry_service.send_agent_command(Path("/does/not/exist"), "a" * 64, "CMD:EXECUTE:ps1:ZmFrZQ==", "req-1")

if __name__ == "__main__":
    unittest.main()
