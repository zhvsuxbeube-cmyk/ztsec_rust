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

## Workspace target selection

The preflight intentionally does not use Cargo `--all-targets`. The previous Linux run showed that `--all-targets` caused Cargo to check upstream Arti test targets from a path dependency; Arti 0.46.0 has feature-gated internal tests that are not part of this application's supported feature set. The ZTSEC workspace is instead checked with its normal library/binary targets, and its own workspace tests are run separately with `cargo test --workspace`. This avoids modifying or forking Arti simply to satisfy an application-level CI gate.

## CI cargo-check logs

The Linux server package explicitly declares the `ztsec-server` binary target so CI produces the documented executable name. The Linux hosted runner executes `cargo check --workspace`; the Windows hosted runner executes `cargo check --package ztsec_agent` because `ztsec_server` is Linux-only. These are the application workspace targets, excluding upstream dependency test targets. Both run these checks before dependency generation, tests, or release builds. The complete stdout/stderr is captured to `linux_log.log` on Linux and `windows_log.log` on Windows and uploaded as separate workflow artifacts even when `cargo check` fails. These logs are intended to preserve every compiler error and warning emitted by the preflight check.

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

The supplied Arti 0.46.0 source is intentionally unchanged. Its upstream
`tor-dirclient` `LZMA_DICT_MEM_LIMIT` dead-code warning is retained as an upstream warning
rather than modifying or forking Arti. CI now explicitly checks that `vendor/arti` remains
unchanged. The output source ZIP excludes the unchanged `vendor/arti` tree because the same
vendor source is already present in the GitHub repository.

## CI log repair — latest build failure

The latest Linux log showed `shutdown.changed()` requiring a mutable watch receiver and a Rust 2024 RPIT lifetime capture on `launch_onion_service`; both are fixed. The unused `peer` parameter is renamed.

The latest Windows log showed `LNK1181: cannot open input file sqlite3.lib`. The agent and server now enable Arti 0.46.0's `static-sqlite` feature so libsqlite3 is built from the Arti dependency tree instead of requiring an external Windows `sqlite3.lib`.

## Latest CI log repair

The newly uploaded `Logged.zip` reproduced the Linux failure in the shared agent crate:
`ztsec_agent` referenced plugin-manager methods that existed only in the Windows
implementation. The non-Windows `Host` stub now exposes the complete API used by
`src/net.rs` and `src/legacy_net.rs`, returning bounded errors/empty output as appropriate.
The three Linux unused imports are also platform-gated or made fully-qualified.

The Windows log itself reached successful release compilation and tests. Its only
remaining diagnostic was the upstream `LZMA_DICT_MEM_LIMIT` warning. That warning is
intentionally not modified because `vendor/arti` must remain an untouched copy of the
supplied Arti 0.46.0 source.
## Latest uploaded Linux log repair

The latest hosted run failed at `tools/load-test/src/main.rs:75` with Rust `E0283` because Tungstenite 0.30.0's `Utf8Bytes` has multiple `AsRef` implementations. The load test now uses `Utf8Bytes::as_str()` for the `AUTH:OK` comparison and includes a regression test for that response. No Arti source is modified.


## Latest Linux runner failure analysis

The latest hosted Linux log contained 11 errors, all from `vendor/arti/crates/tor-circmgr` compiled as a `lib test`. The failing symbols (`construct_custom_netdir`, `OwnedPath`, `VanguardMode`, `VanguardMgr`, `testing_rng`, and `pick_path_with_vanguards`) are Arti's internal test-only APIs and are not required by the ZTSEC application.

The underlying cause was workspace membership: Cargo automatically includes path dependencies located inside the workspace directory unless they are explicitly excluded. The ZTSEC workspace depends on vendored Arti by path, so `cargo test --workspace` was selecting Arti's own unit-test targets. The root workspace now explicitly excludes `vendor/arti`. This keeps Arti available as a normal path dependency while preventing its independent test targets from becoming ZTSEC workspace members.

No Arti source was modified.

## Latest Linux runner failure: vendored Arti workspace membership

The supplied Linux runner log contained 11 errors while compiling `vendor/arti/crates/tor-circmgr` as `lib test`. These were Arti's internal test-only symbols (`construct_custom_netdir`, `OwnedPath`, `VanguardMode`, `VanguardMgr`, `testing_rng`, and `pick_path_with_vanguards`) and were not ZTSEC application errors.

The underlying Cargo behavior is that path dependencies located inside a workspace directory can be discovered as workspace members unless explicitly excluded. Because ZTSEC uses vendored Arti by path, `cargo test --workspace` was selecting Arti test targets. The root workspace now contains `exclude = ["vendor/arti"]`. Arti remains a normal path dependency of the agent/server, but its independent tests are not selected by ZTSEC workspace commands.

No Arti source was modified.

## Latest uploaded Linux log repair (2026-09-30)

The uploaded Linux log contained 11 errors from `vendor/arti/crates/tor-circmgr` compiled as `lib test`. No ZTSEC package was failing in that section of the log.

The root cause was that `vendor/arti` is a path dependency located under the ZTSEC workspace directory. Cargo can automatically discover such path dependencies as workspace members unless the path is explicitly excluded. The root workspace now declares:

```toml
exclude = ["vendor/arti"]
```

This keeps Arti available as a normal path dependency for the ZTSEC agent/server while preventing `cargo test --workspace` from selecting Arti's own test targets. No Arti source was changed.

A CI preflight script (`tools/verify_workspace.py`) is run on both Linux and Windows before Cargo validation to ensure the exclusion remains present.

## Linux binary production guard
The server package explicitly declares the hyphenated `ztsec-server` binary target used by CI, Docker, local integration, deployment, and release packaging. After the Linux release build, CI verifies that `target/release/ztsec-server` exists, is executable, and is non-empty before attempting artifact upload.

### CI shell-script execution

`tools/local_integration.sh` is executed explicitly with Bash in GitHub Actions after `chmod +x`, avoiding failures caused by checkout/filesystem executable-bit metadata.
