# Update implementation checkpoint

Current phase: packaging and verification

Completed:
- Traced the existing ztsec_agent command, panel, mutex, process, connection, and CI paths.
- Traced Mirage's update/handoff/mutex patterns and adapted only the relevant lifecycle ideas.
- Added `CMD:UPDATE:<filename>:<base64-executable>` with bounded binary decoding and PE validation.
- Added Windows executable-directory resolution, one-file final installation, inherited-pipe handoff, transaction token, mutex gate/successor ownership, and post-exit old-image cleanup.
- Added panel Update controls and intentional reconnect handling.
- Added unit/static contracts, process-level update tests, and a panel-level update test.
- Added both update tests to the existing Windows GitHub Actions workflow.

Verified in this environment:
- Python syntax checks for all panel/test tools.
- YAML parsing for the GitHub Actions workflow.
- Static contracts for update APIs, filename/path safety, no update CLI arguments, IPC, mutex handoff, and single-file implementation.
- Final diff restricted to Update integration, focused documentation/checkpoint, tests, and CI.
- Final ZIP extraction and post-package static checks.

Environment limitation:
- This execution environment has no Rust toolchain and no Windows runtime, so `cargo test`, the MSVC build, and Windows process/panel harnesses cannot be executed locally.
- GitHub Actions is configured to run the Rust test/build plus both Windows update harnesses on `windows-latest`; no remote CI run was available from this session, so CI is configured but not claimed as remotely executed.

Platform note:
- Under the strict single-file/no-staging requirement, the updater rejects an in-place update whose target filename equals the running executable filename. Windows keeps the active executable image mapped/locked; the panel therefore exposes `update-as:<filename>:<path>` for a distinct final successor filename. The old image is removed only after the successor is live.
