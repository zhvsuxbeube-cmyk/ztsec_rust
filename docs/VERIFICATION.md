# Verification record

This file records what was actually verified in the supplied build environment.

## Environment

- Python: 3.13.x
- Rust/Cargo: not installed in the execution environment
- Docker: not installed in the execution environment
- Clang/lld-link: present, but not sufficient to run the Rust build without Cargo/rustc
- External network access from the execution environment: unavailable

## PASSED

- `python3 -m py_compile telemetry_service.py python_service.py tools/test_python_service.py tools/panel.py tools/panel_test.py tools/test_update_contract.py`
- `python3 -m unittest -v tools.test_python_service tools.panel_test` (6 tests)
- `python3 tools/test_update_contract.py`
- `bash -n tools/local_integration.sh`
- Static repository checks for old/direct transport compatibility, embedded Arti dependency wiring, authentication configuration, bounded protocol sizes, and absence of placeholder TODOs in required production paths.
- YAML structure review of `.github/workflows/build.yml` and Dockerfile/source path review.

## NOT RUN

- Cargo formatting, compilation, unit tests, and release builds for the agent/server/tools (Cargo/rustc unavailable locally).
- Windows `x86_64-pc-windows-msvc` release build (MSVC/Rust toolchain unavailable locally).
- Docker build (Docker unavailable locally).
- Rust local integration test (`tools/local_integration.sh`) because the required release binaries cannot be produced locally.
- Live Tor/.onion end-to-end test because the Rust binaries cannot be produced locally and external networking is unavailable.
- Connection load test, CPU/memory measurement, and per-connection benchmark. No benchmark figures are claimed.

## CI intent

The GitHub Actions workflow installs Rust 1.92, runs workspace tests, builds the release binaries, runs Python validation, executes the deterministic local integration path, and builds the reproducible Docker server image. A live Internet Tor dependency is intentionally not part of the mandatory CI path.

## CI manifest fix (2026-09-30)

GitHub Actions initially failed during `cargo generate-lockfile` because `server/Cargo.toml`
listed `tor-rtcompat/tokio` and `tor-rtcompat/native-tls` as features of the direct
`tor-hsservice` dependency. Cargo only permits `package/feature` activation for
transitive dependencies from the package's own `[features]` table.

The fixed server manifest keeps `tor-hsservice` featureless (`default-features = false`).
The required Tokio/native-TLS runtime features are enabled through the direct
`tor-rtcompat` dependency, while `arti-client` continues to request its supported
`onion-service-service` feature, which activates `tor-hsservice` as intended.
The invalid `tor-rtcompat/tokio` and `tor-rtcompat/native-tls` entries are no longer
listed as direct dependency features.

## CI cargo-check logs

The Linux hosted runner executes `cargo check --workspace --all-targets`; the Windows hosted runner executes `cargo check --package ztsec_agent --all-targets` because `ztsec_server` is Linux-only. Both run these checks before dependency generation, tests, or release builds. The complete stdout/stderr is captured to `linux_log.log` on Linux and `windows_log.log` on Windows and uploaded as separate workflow artifacts even when `cargo check` fails. These logs are intended to preserve every compiler error and warning emitted by the preflight check.

## CI #90 error inventory

The uploaded `Logs.zip` was reviewed line-by-line for compiler diagnostics. The Linux run
reported three compilation errors and one project-owned warning: `HsId` was incorrectly
formatted through `Display`; `Server` was moved into `websocket_session` and then reused;
the WebSocket handshake error was not converted into `io::Error`; and an unnecessary
`mut` was present on the rendezvous-request stream. The Windows run completed `cargo
check` successfully but reported two project-owned dead-code warnings (`LEGACY_RETRY`
and `Endpoint::display_target`) plus one warning from the supplied upstream Arti
`tor-dirclient` crate (`LZMA_DICT_MEM_LIMIT`).

All project-owned diagnostics above are fixed. The Arti warning remains confined to the
vendored upstream source because changing it would create an unnecessary Arti fork.

## CI log capture update (2026-09-30)

The workflow now appends Cargo output from dependency lock generation, Rust tests, and
release/tool builds to the same platform log after the mandatory `cargo check` preflight.
The Windows MSVC environment is initialized before the preflight and all subsequent
Cargo commands. This ensures later compiler/linker errors and warnings are retained in
`linux_log.log` or `windows_log.log`, not only errors from the initial check.

The upstream Arti `tor-dirclient` warning about `LZMA_DICT_MEM_LIMIT` is emitted by the
vendored Arti 0.46.0 source and is not modified here; changing upstream warning behavior
would unnecessarily fork the supplied Arti source.
