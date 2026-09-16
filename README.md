# ztsec_agent

Windows CLI agent with a small C ABI plugin host.

## Build

```text
cargo test
cargo build --release --target x86_64-pc-windows-msvc
```

## Run

```text
ztsec_agent.exe
ztsec_agent.exe --ip 127.0.0.1 --port 4793
```

## Plugin

Plugins export `PluginOnLoad`, `PluginOnEvent`, and `PluginOnUnload` from a DLL.

The sample is `plugin/hello.cpp`.

The test panel is:

```text
python tools/panel.py --port 4793
```

At `>` enter the full DLL path.

CI builds the sample DLL, checks its exports, loads it through the agent, verifies the plugin ACK, and closes the session.


## Update flow

The panel can send a replacement executable as file bytes:

```text
update:C:\path\to\ztsec_agent.exe
```

The wire command is `CMD:UPDATE:<sha256>:<base64-bytes>`. The agent verifies the SHA-256 before staging the bytes, re-verifies the staged file, starts a one-shot successor, acknowledges the scheduled handoff, and exits. The temporary successor helper waits for the old process to exit, verifies the staged file again, replaces the original executable at the same path and filename, and starts the new agent from that original location. A failed promotion attempts to restore the previous executable. The update hashing path keeps its I/O buffer on the heap so the Windows 1 MiB main-thread stack is not exhausted by large local arrays.

CI exercises this end-to-end on Windows, including rejection of a tampered payload, successful promotion, reconnect of the updated binary, and a clean close handshake.


### Update handoff state machine

The update path is fail-closed in three phases:

1. The running agent validates and durably stages the payload and starts an isolated successor helper.
2. The successor launches the exact staged image in probe mode; the server must acknowledge the probe and the probe must complete the local handoff before the original agent sends `ACK:UPDATE:`.
3. After the original process exits, the helper replaces the original executable path, launches the new image with the original arguments plus an internal final-readiness token, and waits for the new normal-mode process to reconnect to the server and prove the installed file hash/fingerprint. Only then is the backup discarded. A failed final readiness path kills the candidate, restores the original image, and restarts it.

The installed executable therefore keeps its original path and filename.
