import argparse
import socket
import subprocess
import sys
import time
from pathlib import Path


def read_line(conn, timeout):
    conn.settimeout(timeout)
    data = bytearray()
    while True:
        b = conn.recv(1)
        if not b:
            return None
        if b == b"\n":
            return bytes(data).decode().strip()
        data.extend(b)
        if len(data) > 4096:
            raise RuntimeError("protocol line too long")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--timeout", type=float, default=60.0)
    args = ap.parse_args()

    root = Path(__file__).resolve().parent
    original = root / "original.py"
    update = root / "update.py"

    with socket.create_server(("127.0.0.1", 0)) as server:
        port = server.getsockname()[1]
        proc = subprocess.Popen(
            [sys.executable, str(original), "--host", "127.0.0.1", "--port", str(port), "--update", str(update)],
            cwd=str(root),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            server.settimeout(args.timeout)
            conn, _ = server.accept()
            with conn:
                if read_line(conn, 10) != "ORIGINAL":
                    raise RuntimeError("original did not connect")
                print("[python-handoff] original connected", flush=True)
                conn.sendall(b"UPDATE\n")
                if read_line(conn, 10) is not None:
                    raise RuntimeError("original did not disconnect for update")

            print("[python-handoff] original disconnected", flush=True)
            deadline = time.monotonic() + args.timeout
            while time.monotonic() < deadline:
                remaining = max(0.1, deadline - time.monotonic())
                server.settimeout(min(1.0, remaining))
                try:
                    conn, _ = server.accept()
                except socket.timeout:
                    if proc.poll() is not None:
                        break
                    continue
                with conn:
                    greeting = read_line(conn, min(10, remaining))
                    if greeting != "UPDATE":
                        raise RuntimeError(f"update process sent an unexpected greeting: {greeting!r}")
                    conn.sendall(b"OK\n")
                print("[python-handoff] update connected", flush=True)
                break
            else:
                raise RuntimeError("update process did not reconnect within 60 seconds")

            try:
                out, err = proc.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                out, err = proc.communicate(timeout=5)
                raise RuntimeError(f"original did not exit after update success; stdout={out!r}; stderr={err!r}")
            if proc.returncode != 0:
                raise RuntimeError(f"original failed: stdout={out!r}; stderr={err!r}")
            if "SUCCESS" not in out:
                raise RuntimeError(f"original did not receive success from update: stdout={out!r}; stderr={err!r}")
            print("[python-handoff] passed", flush=True)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=5)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"[python-handoff] failed: {exc}", file=sys.stderr)
        raise
