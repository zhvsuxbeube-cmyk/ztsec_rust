import argparse
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--agent", required=True)
    args = ap.parse_args()

    agent = Path(args.agent).resolve()
    panel = Path(__file__).resolve().parent / "panel.py"
    if not agent.is_file():
        raise SystemExit(f"missing agent: {agent}")

    with tempfile.TemporaryDirectory(prefix="ztsec-panel-update-test-") as root_name:
        root = Path(root_name)
        install = root / "install"
        install.mkdir()
        old = install / "ztsec_agent.exe"
        old.write_bytes(agent.read_bytes())
        payload = agent.read_bytes()
        before = {p.name for p in install.iterdir()}

        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]

        panel_proc = subprocess.Popen(
            [sys.executable, str(panel), "--ip", "127.0.0.1", "--port", str(port)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=str(panel.parent.parent),
        )
        agent_proc = subprocess.Popen(
            [str(old), "--ip", "127.0.0.1", "--port", str(port)],
            cwd=str(root),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            time.sleep(1.0)
            if agent_proc.poll() is not None:
                raise RuntimeError(f"agent exited before panel update: {agent_proc.returncode}")
            if panel_proc.poll() is not None:
                out, err = panel_proc.communicate(timeout=2)
                raise RuntimeError(f"panel exited early: {out}\n{err}")
            if panel_proc.stdin is None:
                raise RuntimeError("panel stdin is unavailable")

            # Exercise the real panel command parser; it sends the real UPDATE wire command.
            panel_proc.stdin.write(f"update:{agent}\n")
            panel_proc.stdin.flush()

            time.sleep(5)
            if agent_proc.poll() is None:
                agent_proc.wait(timeout=20)

            # The panel explicitly reconnects after an update ACK. Close the restored session.
            panel_proc.stdin.write("close\n")
            panel_proc.stdin.flush()
            out, err = panel_proc.communicate(timeout=20)
            output = out
            if panel_proc.returncode != 0:
                raise RuntimeError(f"panel failed: {output}\n{err}")
            if "update handoff accepted; waiting for successor" not in output:
                raise RuntimeError(f"panel did not enter update handoff state: {output}")
            if "update restored" not in output:
                raise RuntimeError(f"panel did not observe successor reconnection: {output}")
            if "ACK:CLOSE" not in output:
                raise RuntimeError(f"panel did not close restored session: {output}")

            deadline = time.time() + 10
            while time.time() < deadline:
                names = {p.name for p in install.iterdir()}
                if names == {old.name}:
                    break
                time.sleep(0.25)
            names = {p.name for p in install.iterdir()}
            if names != {old.name}:
                raise RuntimeError(f"panel update left unexpected files: {names}; before={before}")
            if old.read_bytes() != payload:
                raise RuntimeError("panel-installed bytes differ from payload")
        finally:
            if agent_proc.poll() is None:
                agent_proc.terminate()
                try:
                    agent_proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    agent_proc.kill()
                    agent_proc.wait(timeout=5)
            if panel_proc.poll() is None:
                panel_proc.terminate()
                try:
                    panel_proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    panel_proc.kill()
                    panel_proc.wait(timeout=5)

    print("update panel test passed")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"update panel test failed: {exc}", file=sys.stderr)
        raise
