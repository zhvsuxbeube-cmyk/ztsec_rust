# CI build-log analysis

## Linux

The supplied Linux log failed in `server/src/lib.rs` with two compiler errors and one project-owned warning:

- `E0596`: the `watch::Receiver` used by the metrics task was not mutable, even though `changed()` requires `&mut self`.
- `E0597`: Rust 2024 return-position `impl Trait` capture caused `launch_onion_service` to appear to retain a borrow of `self` when the returned request stream was moved into `tokio::spawn`.
- `peer` was an unused parameter in `websocket_session`.

Fixes:

- `let mut shutdown = self.shutdown.subscribe();`
- `launch_onion_service` now uses precise RPIT capture: `impl Stream<...> + use<>`. This matches the Rust 2024 capture model and the supplied Arti 0.46.0 API's own use of precise capture.
- `peer` is now `_peer` because that function does not use it.

## Windows

The supplied Windows log reached linking and failed with:

`LINK : fatal error LNK1181: cannot open input file 'sqlite3.lib'`

The Arti 0.46.0 source supplied with the repository provides `arti-client` build features `static-sqlite` and `static`. `static-sqlite` enables `tor-dirmgr/static`, which enables `rusqlite/bundled` and builds SQLite as part of the Cargo dependency graph. The agent and server now enable `arti-client/static-sqlite`, removing the Windows dependency on a separately installed `sqlite3.lib`.

The Windows log also contains the upstream Arti `tor-dirclient` `LZMA_DICT_MEM_LIMIT` dead-code warning. The supplied Arti source was not modified merely to hide that upstream warning; this avoids unnecessarily forking vendored Arti.

## Verification policy

The exact uploaded CI logs are retained as `linux_log.log` and `windows_log.log`. A new hosted-runner Cargo check must be treated as the authoritative compiler validation because this execution environment does not provide `cargo`, `rustc`, or Docker.
