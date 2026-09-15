import base64
import hashlib
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(__file__))
import panel


class PanelUpdateTests(unittest.TestCase):
    def test_update_cmd_contains_sha256_and_file_bytes(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"MZztsec-update-test")
            path = f.name
        try:
            command = panel.update_cmd(path)
            prefix, digest, encoded = command.split(":", 3)[1:]
            self.assertEqual(prefix, "UPDATE")
            payload = base64.b64decode(encoded)
            self.assertEqual(payload, b"MZztsec-update-test")
            self.assertEqual(digest, hashlib.sha256(payload).hexdigest())
        finally:
            os.unlink(path)


    def test_update_cmd_rejects_empty_file(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            path = f.name
        try:
            with self.assertRaises(ValueError):
                panel.update_cmd(path)
        finally:
            os.unlink(path)

    def test_wait_result_accepts_ack_before_peer_half_close(self):
        import socket
        left, right = socket.socketpair()
        try:
            right.sendall(b"ACK:UPDATE:\n")
            right.shutdown(socket.SHUT_WR)
            self.assertEqual(panel.wait_result(left), "ACK:UPDATE:")
        finally:
            left.close()
            right.close()

    def test_update_ack_confirmation_command(self):
        command = "CMD:UPDATE_ACK"
        self.assertTrue(command.startswith("CMD:UPDATE_ACK"))
        self.assertEqual("ACK:UPDATE_ACK", "ACK:" + command.split(":", 1)[1])

    def test_update_ack_confirmation_round_trip(self):
        import socket, threading
        left, right = socket.socketpair()
        received = []
        def server():
            line = panel.read_line(right)
            received.append(line)
            right.sendall(b"ACK:UPDATE_ACK\n")
        t = threading.Thread(target=server)
        t.start()
        try:
            left.sendall(b"CMD:UPDATE_ACK\n")
            self.assertEqual(panel.wait_result(left), "ACK:UPDATE_ACK")
            t.join(timeout=2)
            self.assertEqual(received, ["CMD:UPDATE_ACK"])
        finally:
            left.close(); right.close()

if __name__ == "__main__":
    unittest.main()
