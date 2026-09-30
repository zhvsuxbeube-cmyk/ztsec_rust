# CI build-log analysis — latest uploaded logs

## Linux

The uploaded Linux log failed while checking `ztsec_agent`. The server crate reached successful checking before the agent failure. The remaining failures were all platform-conditional plugin API mismatches:

- `Host::drain_outputs()` was missing on non-Windows.
- `Host::begin_transfer()` was missing on non-Windows.
- `Host::resume_transfer()` was missing on non-Windows.
- `Host::append_transfer()` was missing on non-Windows.
- `Host::finish_transfer()` was missing on non-Windows.

The same five API calls occur in both `src/net.rs` and `src/legacy_net.rs`. The Windows implementation already supplied them through the real plugin manager, but the non-Windows stub exposed only `new`, `load`, `event`, `unload`, and `clear`.

Project-owned warnings in the same Linux log were:

- unused `HashMap` import in `src/plugin.rs`;
- unused `Command` import in `src/telemetry.rs`;
- unused `OsStr` import in `src/update.rs`.

All three imports are now platform-gated or made fully-qualified.

## Windows

The uploaded Windows log successfully completed the agent release build and its tests. The only warning was from the supplied Arti 0.46.0 `tor-dirclient` source:

`LZMA_DICT_MEM_LIMIT` was defined even when the `xz` feature was disabled.

This upstream warning is intentionally left unchanged. The supplied Arti 0.46.0 source is not modified or forked. The complete unchanged `vendor/arti` tree is excluded from output archives because it is already present in the GitHub repository.

## Verification policy

The exact uploaded logs are retained as `linux_log.log` and `windows_log.log`. Local `cargo check` is still unavailable in this execution environment because Rust/Cargo are not installed, so hosted Linux and Windows runners remain the authoritative compile validation.
