import base64, socket, sys

def read_line(s):
    b = bytearray()
    while True:
        c = s.recv(1)
        if not c or c == b"\n":
            return bytes(b).decode(errors="replace").rstrip("\r")
        b.extend(c)

def pump(s, want_prefix):
    while True:
        line = read_line(s)
        if not line:
            sys.exit(1)
        if line == "HB":
            s.sendall(b"PONG\n")
            continue
        if line.startswith(want_prefix):
            return
        if line.startswith("ERR:"):
            sys.exit(1)

port = int(sys.argv[1]) if len(sys.argv) > 1 else 4795
path = sys.argv[2] if len(sys.argv) > 2 else None

with socket.create_server(("127.0.0.1", port)) as srv:
    conn, _ = srv.accept()
    with conn:
        read_line(conn)
        read_line(conn)
        with open(path, "rb") as f:
            data = f.read()
        b64 = base64.b64encode(data).decode()
        conn.sendall(f"CMD:EXECUTE:ps1:{b64}\n".encode())
        pump(conn, "ACK:EXECUTE:")
        conn.sendall(b"CMD:CLOSE\n")
        pump(conn, "ACK:CLOSE")
