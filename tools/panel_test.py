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


if __name__ == "__main__":
    unittest.main()
