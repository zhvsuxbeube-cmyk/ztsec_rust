import argparse
import base64
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

MAX_LINE = 96 * 1024 * 1024


def read_line(conn):
    data = bytearray()
    while True:
        chunk = conn.recv(4096)
        if not chunk:
            return None
        data.extend(chunk)
        if len(data) > MAX_LINE:
            raise RuntimeError("wire line too large")
        pos = data.find(b"\n")
        if pos >= 0:
            return bytes(data[:pos]).decode("utf-8", errors="replace").rstrip("\r")


def wait_for_result(conn, timeout=30):
    conn.settimeout(timeout)
    while True:
        line = read_line(conn)
        if line is None:
            raise RuntimeError("agent disconnected before result")
        if line == "HB":
            conn.sendall(b"PONG\n")
            continue
        if line.startswith("DATA:"):
            continue
        if line.startswith("ACK:") or line.startswith("ERR:"):
            return line


def accept_agent(server, timeout=30):
    deadline = time.time() + timeout
    last_error = "no complete agent handshake"
    server.settimeout(min(2.0, timeout))
    while time.time() < deadline:
        try:
            conn, _ = server.accept()
        except socket.timeout:
            continue
        remaining = max(1.0, deadline - time.time())
        conn.settimeout(min(remaining, 10.0))
        keep = False
        try:
            hello = read_line(conn)
            if not hello or not hello.startswith("HELLO:FINGERPRINT:"):
                last_error = f"unexpected hello: {hello!r}"
                continue
            data = read_line(conn)
            if not data or not data.startswith("DATA:"):
                last_error = f"unexpected data: {data!r}"
                continue
            keep = True
            return conn
        except (OSError, RuntimeError) as exc:
            last_error = str(exc)
        finally:
            if not keep and conn.fileno() != -1:
                conn.close()
    raise RuntimeError(last_error)


def send_update(conn, filename, payload):
    encoded = base64.b64encode(payload).decode("ascii")
    conn.sendall(f"CMD:UPDATE:{filename}:{encoded}\n".encode("ascii"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--agent", required=True)
    args = ap.parse_args()

    agent = Path(args.agent).resolve()
    if not agent.is_file():
        raise SystemExit(f"missing agent: {agent}")

    with tempfile.TemporaryDirectory(prefix="ztsec-update-test-") as root_name:
        root = Path(root_name)
        install = root / "install"
        install.mkdir()
        old = install / "ztsec_agent.exe"
        new = install / "ztsec_agent_update.exe"
        source = root / "payload.exe"
        old.write_bytes(agent.read_bytes())
        source.write_bytes(agent.read_bytes())
        original = {p.name for p in install.iterdir()}
        if original != {old.name}:
            raise RuntimeError(f"unexpected initial install directory: {original}")

        with socket.socket() as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(("127.0.0.1", 0))
            server.listen(4)
            port = server.getsockname()[1]

            proc = subprocess.Popen(
                [str(old), "--ip", "127.0.0.1", "--port", str(port)],
                cwd=str(install),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            try:
                conn = accept_agent(server)
                with conn:
                    # Invalid PE uses the real command dispatcher and must be rejected in-place.
                    conn.sendall(b"CMD:UPDATE:rejected.exe:AAECAwQF\n")
                    result = wait_for_result(conn)
                    if not result.startswith("ERR:UPDATE:"):
                        raise RuntimeError(f"invalid update was not rejected: {result}")

                    # Traversal is rejected before any filesystem write.
                    conn.sendall(b"CMD:UPDATE:..\\escape.exe:AAECAwQF\n")
                    result = wait_for_result(conn)
                    if not result.startswith("ERR:UPDATE:"):
                        raise RuntimeError(f"traversal was not rejected: {result}")

                    # A valid PE that is not an agent must fail the authenticated handoff
                    # without destroying the currently running installation.
                    system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
                    broken = system_root / "System32" / "where.exe"
                    if not broken.is_file():
                        raise RuntimeError(f"missing Windows test payload: {broken}")
                    send_update(conn, "failed_update.exe", broken.read_bytes())
                    result = wait_for_result(conn)
                    if result != "ACK:UPDATE:failed_update.exe":
                        raise RuntimeError(f"unexpected failure-case acknowledgement: {result}")

                # The old installation must remain running after the successor fails handoff.
                conn_failed = accept_agent(server, timeout=45)
                with conn_failed:
                    conn_failed.sendall(b"CMD:REQ:DATA\n")
                    if wait_for_result(conn_failed, timeout=15) != "PONG":
                        raise RuntimeError("old installation was not usable after failed update")
                    if (install / "failed_update.exe").exists():
                        raise RuntimeError("failed update left an installed executable behind")

                    payload = source.read_bytes()
                    send_update(conn_failed, new.name, payload)
                    result = wait_for_result(conn_failed)
                    if result != f"ACK:UPDATE:{new.name}":
                        raise RuntimeError(f"unexpected update acknowledgement: {result}")

                # The old session intentionally closes; the successor must reconnect.
                proc.wait(timeout=45)
                proc = None
                conn2 = accept_agent(server, timeout=45)
                with conn2:
                    conn2.sendall(b"CMD:REQ:DATA\n")
                    if wait_for_result(conn2, timeout=15) != "PONG":
                        raise RuntimeError("successor did not answer REQ:DATA")
                    # The replacement must own the normal mutex while it is running.
                    probe = subprocess.Popen(
                        [str(new), "--ip", "127.0.0.1", "--port", str(port + 1)],
                        cwd=str(install),
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                    probe.wait(timeout=10)
                    if probe.returncode != 0:
                        raise RuntimeError(f"second normal start returned {probe.returncode}")

                    conn2.sendall(b"CMD:CLOSE\n")
                    if wait_for_result(conn2, timeout=15) != "ACK:CLOSE":
                        raise RuntimeError("successor did not close normally")

                deadline = time.time() + 10
                while time.time() < deadline:
                    names = {p.name for p in install.iterdir()}
                    if names == {new.name}:
                        break
                    time.sleep(0.25)
                names = {p.name for p in install.iterdir()}
                if names != {new.name}:
                    raise RuntimeError(f"update created or preserved unexpected files: {names}")
                if new.read_bytes() != source.read_bytes():
                    raise RuntimeError("installed bytes differ from payload")

            finally:
                if proc is not None and proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=5)

    print("update process test passed")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"update process test failed: {exc}", file=sys.stderr)
        raise
