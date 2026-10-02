import base64
import hashlib
import hmac
import tempfile
import unittest
from pathlib import Path

from tools import panel


class PanelGatewayProtocolTests(unittest.TestCase):
    def test_secret_is_never_needed_to_build_wire_hello_or_challenge_response(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "secret"
            path.write_text("12345678901234567890123456789012\n", encoding="ascii")
            secret = panel._read_panel_secret(path)
            challenge = bytes(range(32))
            panel_id = "panel-01"
            message = panel.PANEL_AUTH_DOMAIN + panel_id.encode() + b"\0" + challenge
            proof = hmac.new(secret, message, hashlib.sha256).digest()
            self.assertEqual(len(proof), 32)
            wire = {"message_type": "panel_proof", "panel_id": panel_id, "proof": base64.b64encode(proof).decode().rstrip("=")}
            self.assertNotIn(secret.decode(), str(wire))

    def test_secret_generator_creates_exactly_32_ascii_characters(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "secret"
            panel._write_panel_secret(path)
            value = path.read_text(encoding="ascii").strip()
            self.assertEqual(len(value), 32)
            self.assertTrue(value.isascii() and value.isprintable())


    def test_command_frame_uses_shared_control_shape(self):
        request, request_id = panel.panel_command(
            "a" * 64,
            "CMD:EXECUTE:ps1:ZmFrZQ==",
        )
        self.assertEqual(request["protocol_version"], panel.PANEL_PROTOCOL_VERSION)
        self.assertEqual(request["message_type"], "agent_command")
        self.assertEqual(request["request_id"], request_id)
        self.assertEqual(request["target"], "a" * 64)
        self.assertEqual(request["command"], "CMD:EXECUTE:ps1:ZmFrZQ==")

    def test_remote_command_builder_covers_full_current_vocabulary(self):
        target = "b" * 64
        cases = {
            "data": "REQ:DATA",
            "close": "CMD:CLOSE",
            "reconnect": "CMD:RECONNECT",
            "sleep": "CMD:SLEEP",
            "hibernate": "CMD:HIBERNATE",
            "restart": "CMD:RESTART",
            "shutdown": "CMD:SHUTDOWN",
            "unload:plug": "CMD:UNLOAD:plug",
            "event:ping": "CMD:PLUGIN_EVENT:ping",
            "send:CMD:DIRECT_CONNECT": "CMD:DIRECT_CONNECT",
        }
        for raw, expected in cases.items():
            _, command = panel.parse_remote_command(raw, target)
            self.assertEqual(command, expected)

    def test_remote_frame_limit_matches_control_plane_limit(self):
        self.assertEqual(panel.MAX_PANEL_FRAME_BYTES, panel.MAX_CONTROL_COMMAND_BYTES + 64 * 1024)
        self.assertGreater(panel.MAX_PANEL_FRAME_BYTES, 3 * 1024 * 1024)
    def test_frame_rejects_oversized_payload(self):
        class Sink:
            def sendall(self, _):
                raise AssertionError("sendall should not be reached")
        with self.assertRaises(ValueError):
            panel._panel_send(Sink(), {"data": "x" * panel.MAX_PANEL_FRAME_BYTES})


if __name__ == "__main__":
    unittest.main()
