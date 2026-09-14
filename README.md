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

## Update

The existing command channel accepts `CMD:UPDATE:<filename>:<base64-executable>`. The panel exposes `update:<path>` and `update-as:<filename>:<path>`.

The update writes exactly one final executable in the directory returned by the Windows `GetModuleFileNameW` API. The filename is normalized to `.exe` and is treated as a single path component; traversal and absolute paths are rejected.

Windows keeps the active executable image mapped, so this implementation does not overwrite the currently running executable in place. Under the single-file/no-staging constraint, the update filename therefore must differ from the running executable filename; the successor is launched from the new final path, takes over the normal mutex through an authenticated inherited-pipe handoff, and deletes the old executable after the old process exits.

The update handoff uses no update-specific command-line arguments, environment markers, registry state, or update sidecar files. The existing command connection remains the trust boundary for the update command.
