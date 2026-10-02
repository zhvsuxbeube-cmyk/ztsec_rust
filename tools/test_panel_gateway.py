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

    def test_frame_rejects_oversized_payload(self):
        class Sink:
            def sendall(self, _):
                raise AssertionError("sendall should not be reached")
        with self.assertRaises(ValueError):
            panel._panel_send(Sink(), {"data": "x" * panel.MAX_PANEL_FRAME_BYTES})


if __name__ == "__main__":
    unittest.main()
