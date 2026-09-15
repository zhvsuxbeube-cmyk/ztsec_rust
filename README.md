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

The wire command is `CMD:UPDATE:<sha256>:<base64-bytes>`. The agent verifies the SHA-256 before staging the bytes, re-verifies the staged file, launches a one-shot successor, and exits. The temporary successor helper waits for the old process to exit, verifies the staged file again, replaces the original executable at the same path and filename, and starts the new agent from that original location. A failed promotion attempts to restore the previous executable.

CI exercises this end-to-end on Windows, including rejection of a tampered payload, successful promotion, reconnect of the updated binary, and a clean close handshake.
