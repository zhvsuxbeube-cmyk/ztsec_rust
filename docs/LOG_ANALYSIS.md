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


## Linux — latest failure (2026-09-30)

The latest hosted Linux preflight failed after `ztsec_server` and `ztsec_agent` had checked successfully. `tools/load-test` failed because `tokio_tungstenite::connect_async_with_config` is gated behind the crate's `connect` feature; the load-test crate previously enabled only `handshake`. The ten follow-on type-inference errors were consequences of that missing import.

The same run then checked an upstream `tor-circmgr` library test from the vendored Arti dependency and reported feature-gated test symbols such as `VanguardMgr`, `OwnedPath`, and `construct_custom_netdir`. These are not ZTSEC code defects. The CI gate is corrected to avoid `--all-targets`, which is what brought those dependency test targets into the application check. No Arti source is changed.

Project-owned warnings in the same run were Windows-only symbols being compiled into the Linux build (`fmt_duration`, plugin error strings, registry constants, PowerShell constants, and `PARENT_WAIT`). Those are now cfg-gated so the Linux production target does not carry unused Windows-only items.
## Latest Linux CI failure — `ztsec_load_test` E0283

The newly uploaded Linux log progressed through the ZTSEC server and agent checks and failed only when checking `ztsec_load_test`. The exact error was `E0283` at `tools/load-test/src/main.rs:75`: Tungstenite 0.30.0 defines multiple `AsRef` implementations for `Utf8Bytes`, making `text.as_ref() == "AUTH:OK"` ambiguous. The comparison now uses `text.as_str() == "AUTH:OK"`, which is explicit and allocation-free. A regression unit test was added for the exact authentication response. No file under `vendor/arti` was modified.


## Linux runner failure: vendored Arti selected as workspace member

The latest Linux CI log did not contain a ZTSEC source compilation failure. It contained 11 errors while compiling `tor-circmgr` as a `lib test` under `vendor/arti`.

Root cause: the vendored Arti crates are path dependencies inside the ZTSEC workspace directory. Cargo automatically discovers such path dependencies as workspace members unless they are listed under `[workspace].exclude`. Consequently `cargo test --workspace` selected Arti's own test target, whose feature-gated test helpers were not available under the ZTSEC dependency feature set.

Fix: add `exclude = ["vendor/arti"]` to the root workspace. Arti remains a path dependency and is still compiled as a normal dependency of the ZTSEC agent/server, but its own tests are no longer selected by ZTSEC workspace commands.

Arti source remains byte-for-byte unchanged.

## Latest Linux runner log

The latest Linux failure was not a ZTSEC compiler error. It was the upstream Arti `tor-circmgr` unit-test target being selected by `cargo test --workspace`. The ZTSEC workspace now explicitly excludes `vendor/arti`, which prevents Cargo from treating the vendored path dependency as an application workspace member while retaining it as a normal dependency.

No `vendor/arti` source was changed.

## Latest Linux CI failure — protocol test fixture

The latest Linux runner completed `cargo check` and compilation successfully. The only failing test was
`protocol::tests::parse_existing_telemetry_shape`. Its fixture contained a 66-character hexadecimal fingerprint
while the test asserted the existing 64-character fingerprint contract. The fixture was corrected to 64 characters.
This is a test-data correction; protocol behavior was not changed.

No `vendor/arti` source was modified.

## Latest Linux binary-production failure
The newest Linux log showed that `cargo test --workspace` completed successfully, including all ZTSEC tests. The failure then occurred in the release-build step: Cargo reported `no bin target named ztsec-server` for package `ztsec_server`, with `ztsec_server` suggested as the existing target. The CI/deployment/tooling consistently expect the hyphenated executable `ztsec-server`. The server package now explicitly declares `[[bin]] name = "ztsec-server" path = "src/main.rs"`, aligning Cargo's target name with the intended executable and existing deployment paths.

## Latest Linux binary-production failure
The newest Linux log showed all workspace tests passing, followed by `error: no bin target named ztsec-server`; Cargo reported `ztsec_server` as the available target. This prevented linking and therefore no server executable could be uploaded. The server manifest now explicitly declares `[[bin]] name = "ztsec-server" path = "src/main.rs"`, matching all existing deployment/Docker/integration references. CI also verifies the resulting executable immediately after the release build.

## CI permission-denied failure

The Linux runner reported `tools/local_integration.sh: Permission denied` with exit code 126. The workflow previously executed the file directly. The job now explicitly runs `chmod +x tools/local_integration.sh` followed by `bash tools/local_integration.sh`, so CI no longer depends on repository executable-bit metadata. The script itself is also stored executable in the working tree.

## CI Docker failure: root package target missing

The Linux runner successfully compiled and tested the ZTSEC Rust workspace and produced `target/release/ztsec-server`. The Docker build then failed in its dependency-cache stage because the repository root is itself a Cargo package and the Dockerfile copied only Cargo manifests before running `cargo generate-lockfile`. With no `src/main.rs` present in `/src`, Cargo reported `no targets specified in the manifest`.

The Dockerfile now seeds minimal target source files for every ZTSEC workspace package before `cargo generate-lockfile`; the real source trees are copied afterward and replace those stubs before the release build. This preserves dependency-layer caching while ensuring Cargo can parse the complete application workspace.

No `vendor/arti` source was modified. CI also records the Docker build output in `docker_build.log` and appends it to `linux_log.log`, then extracts `/ztsec-server` from the scratch image and verifies the extracted artifact is non-empty.

## Latest Docker builder failure

The Linux native Rust release build had already succeeded and produced `target/release/ztsec-server`. The Docker build then failed during its dependency-cache layer at `cargo generate-lockfile` because the root workspace referenced `tools/auth-keygen` but the Dockerfile had copied only the root, protocol, server, and Arti manifests. Cargo therefore reported:

`failed to read /src/tools/auth-keygen/Cargo.toml: No such file or directory`

The Dockerfile now copies the `Cargo.toml` files for both ZTSEC tool workspace members before `cargo generate-lockfile`, alongside the existing root/protocol/server manifests. The minimal source targets are still seeded before lockfile generation so each package has a valid target. The real source is copied later for the release build.

No `vendor/arti` source was modified.

## Docker failure: `cp: cannot stat target/release/ztsec-server`

The Dockerfile used a BuildKit `type=cache` mount for `/src/target` during the release build, then attempted to access the generated binary from a later `RUN`. Docker documents cache mounts as build-time cache directories whose contents are not committed as normal image-layer filesystem changes. citeturn909897search0turn909897search11

The release build and copy to `/out/ztsec-server` now happen in the same mounted `RUN`, with explicit non-empty checks. This preserves the target cache while making the exported artifact part of the image filesystem.


## CI failure: scratch Docker artifact image had no command

The Docker `artifacts` stage intentionally uses `FROM scratch`, so the image has no default `CMD` or `ENTRYPOINT`. `docker create ztsec-rust-builder` therefore fails with `no command specified` before `docker cp` can extract `/ztsec-server`. The workflow now creates the container with `/ztsec-server` as its command; `docker create` does not execute the command, and the existing `docker cp` extraction remains unchanged.


## CI failure: Docker scratch image had no command

The artifacts image uses `FROM scratch`, so it has no implicit shell or default `CMD`. The CI previously called `docker create ztsec-rust-builder` without a command, which Docker rejected with `no command specified`. The workflow now calls `docker create ztsec-rust-builder /ztsec-server`; this creates a stopped container configuration and does not execute the server, allowing `docker cp` to extract the ELF binary. The Docker build step also uses `set -euo pipefail` so extraction failures stop the job immediately.


## Management relay hardening

The relay uses a bounded per-agent queue, bounded broadcast fan-out, a separate local control-socket connection limit, and a per-control-connection request rate limit. The relay command vocabulary is intentionally allowlisted to non-code-execution management operations. Direct transport changes require an explicitly configured server endpoint and are runtime-only on the agent.
