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
        chunk = conn.recv(1)
        if not chunk:
            return None
        if chunk == b"\n":
            return bytes(data).decode("utf-8", errors="replace").rstrip("\r")
        data.extend(chunk)
        if len(data) > MAX_LINE:
            raise RuntimeError("wire line too large")


def wait_for_result(conn, timeout=30):
    conn.settimeout(timeout)
    while True:
        line = read_line(conn)
        if line is None:
            raise RuntimeError("agent disconnected before result")
        if line == "HB":
            conn.sendall(b"PONG\n")
            continue
        if line == "PONG":
            return line
        if line.startswith("DATA:"):
            continue
        if line.startswith("ACK:") or line.startswith("ERR:"):
            return line


def process_output(process):
    stdout = b""
    stderr = b""
    if getattr(process, "stdout", None) is not None or getattr(process, "stderr", None) is not None:
        try:
            stdout, stderr = process.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate(timeout=5)
    return stdout.decode("utf-8", errors="replace"), stderr.decode("utf-8", errors="replace")


def accept_agent(server, timeout=45, process=None):
    deadline = time.time() + timeout
    last_error = "timed out"
    server.settimeout(min(2.0, max(0.1, timeout)))
    while time.time() < deadline:
        if process is not None and process.poll() is not None:
            stdout, stderr = process_output(process)
            raise RuntimeError(f"agent exited with code {process.returncode}; stdout={stdout!r}; stderr={stderr!r}")
        try:
            conn, _ = server.accept()
        except socket.timeout:
            continue
        conn.settimeout(10)
        try:
            hello = read_line(conn)
            if hello == "HELLO:UPDATE":
                conn.close()
                continue
            if not hello or not hello.startswith("HELLO:FINGERPRINT:"):
                last_error = f"unexpected hello: {hello!r}"
                conn.close()
                continue
            return conn
        except (ConnectionError, OSError) as exc:
            last_error = f"agent connection failed: {exc}"
            try:
                conn.close()
            except OSError:
                pass
    raise RuntimeError(last_error)


def send_line(conn, line):
    previous = conn.gettimeout()
    conn.settimeout(10)
    try:
        conn.sendall(line.encode("utf-8"))
    finally:
        conn.settimeout(previous)


def send_update(conn, filename, payload):
    encoded = base64.b64encode(payload).decode("ascii")
    previous = conn.gettimeout()
    conn.settimeout(15)
    try:
        conn.sendall(f"CMD:UPDATE:{filename}:{encoded}\n".encode("ascii"))
    finally:
        conn.settimeout(previous)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--agent", required=True)
    args = ap.parse_args()

    agent = Path(args.agent).resolve()
    if not agent.is_file():
        raise SystemExit(f"missing agent: {agent}")

    test_deadline = time.monotonic() + 120
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
                cwd=str(root),
                stdout=None,
                stderr=None,
            )
            try:
                conn = accept_agent(server, process=proc)
                with conn:
                    if time.monotonic() > test_deadline:
                        raise RuntimeError("global update test deadline exceeded")
                    # Invalid PE uses the real command dispatcher and must be rejected in-place.
                    send_line(conn, "CMD:UPDATE:rejected.exe:AAECAwQF\n")
                    result = wait_for_result(conn)
                    if not result.startswith("ERR:UPDATE:"):
                        raise RuntimeError(f"invalid update was not rejected: {result}")
                    # Traversal is rejected before any filesystem write.
                    send_line(conn, "CMD:UPDATE:..\\escape.exe:AAECAwQF\n")
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
                    if result != f"ACK:UPDATE:{new.name}":
                        raise RuntimeError(f"unexpected failure-case acknowledgement: {result}")
                # The old installation must remain running after the successor fails handoff.
                conn_failed = accept_agent(server, timeout=75)
                with conn_failed:
                    send_line(conn_failed, "CMD:REQ:DATA\n")
                    if wait_for_result(conn_failed, timeout=15) != "PONG":
                        raise RuntimeError("old installation was not usable after failed update")
                    conn_failed.settimeout(10)
                    while True:
                        line = read_line(conn_failed)
                        if line == "ERR:UPDATE:FAILED":
                            break
                        if line is None:
                            raise RuntimeError("missing failed update message")
                    if (install / "ztsec_agent_update.exe").exists():
                        raise RuntimeError("failed update left an installed executable behind")
                    payload = source.read_bytes()
                    send_update(conn_failed, new.name, payload)
                    result = wait_for_result(conn_failed)
                    if result != f"ACK:UPDATE:{new.name}":
                        raise RuntimeError(f"unexpected update acknowledgement: {result}")

                # The old session intentionally closes; the successor must reconnect.
                remaining = max(1, int(test_deadline - time.monotonic()))
                proc.wait(timeout=min(30, remaining))
                process_output(proc)
                proc = None
                if time.monotonic() > test_deadline:
                    raise RuntimeError("global update test deadline exceeded before successor reconnect")
                conn2 = accept_agent(server, timeout=min(30, max(1, int(test_deadline - time.monotonic()))))
                with conn2:
                    send_line(conn2, "CMD:REQ:DATA\n")
                    if wait_for_result(conn2, timeout=15) != "PONG":
                        raise RuntimeError("successor did not answer REQ:DATA")
                    # The replacement must own the normal mutex while it is running.
                    with socket.create_server(("127.0.0.1", 0)) as probe_server:
                        probe_port = probe_server.getsockname()[1]
                        probe_server.settimeout(1)
                        probe = subprocess.Popen(
                            [str(old), "--ip", "127.0.0.1", "--port", str(probe_port)],
                            cwd=str(root),
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                        )
                        try:
                            probe.wait(timeout=10)
                        finally:
                            if probe.poll() is None:
                                probe.terminate()
                                probe.wait(timeout=5)
                        if probe.returncode != 0:
                            raise RuntimeError(f"second normal start unexpectedly returned {probe.returncode}")
                        try:
                            accepted, _ = probe_server.accept()
                        except socket.timeout:
                            pass
                        else:
                            accepted.close()
                            raise RuntimeError("second normal start reached the network despite mutex protection")
                    send_line(conn2, "CMD:CLOSE\n")
                    if wait_for_result(conn2, timeout=15) != "ACK:CLOSE":
                        raise RuntimeError("successor did not close normally")

                deadline = min(time.time() + 10, test_deadline)
                while time.time() < deadline:
                    names = {p.name for p in install.iterdir()}
                    if names == {old.name}:
                        break
                    time.sleep(0.25)
                names = {p.name for p in install.iterdir()}
                if names != {old.name}:
                    raise RuntimeError(f"update created or preserved unexpected files: {names}")
                if old.read_bytes() != source.read_bytes():
                    raise RuntimeError("installed bytes differ from payload")

            finally:
                if proc is not None:
                    if proc.poll() is None:
                        proc.terminate()
                        try:
                            proc.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            proc.kill()
                            proc.wait(timeout=5)
                    process_output(proc)

    print("update process test passed")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"update process test failed: {exc}", file=sys.stderr)
        raise
