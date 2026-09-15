import argparse
import socket


def read_line(conn):
    data = conn.recv(4096)
    if not data:
        return None
    return data.split(b"\n", 1)[0].decode().strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, required=True)
    args = ap.parse_args()

    with socket.create_connection((args.host, args.port), timeout=10) as conn:
        conn.sendall(b"UPDATE\n")
        if read_line(conn) != "OK":
            raise RuntimeError("panel did not confirm successor connection")
    print("SUCCESS", flush=True)


if __name__ == "__main__":
    main()
