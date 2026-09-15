import argparse
import socket
import subprocess
import sys
from pathlib import Path


def read_line(conn):
    data = bytearray()
    while b"\n" not in data:
        chunk = conn.recv(4096)
        if not chunk:
            return None
        data.extend(chunk)
        if len(data) > 4096:
            raise RuntimeError("protocol line too long")
    return bytes(data.split(b"\n", 1)[0]).decode().strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--update", required=True)
    args = ap.parse_args()

    with socket.create_connection((args.host, args.port), timeout=10) as conn:
        conn.sendall(b"ORIGINAL\n")
        if read_line(conn) != "UPDATE":
            raise RuntimeError("panel did not request update")
    print("[python-handoff] original: disconnected", flush=True)

    update = Path(args.update)
    result = subprocess.run(
        [sys.executable, str(update), "--host", args.host, "--port", str(args.port)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=60,
        cwd=str(update.parent),
    )
    if result.returncode != 0:
        raise RuntimeError(f"update failed: stdout={result.stdout!r}; stderr={result.stderr!r}")
    if "SUCCESS" not in result.stdout:
        raise RuntimeError(f"update did not report success: {result.stdout!r}")
    print("SUCCESS", flush=True)


if __name__ == "__main__":
    main()
