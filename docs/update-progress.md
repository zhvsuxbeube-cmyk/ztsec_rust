# Update implementation checkpoint

Current phase: final verification

Completed:
- Traced the existing ztsec_agent command, panel, mutex, process, connection, and CI paths.
- Traced Mirage's update/handoff/mutex patterns and adapted only the relevant lifecycle ideas.
- Added `CMD:UPDATE:<filename>:<base64-executable>` with bounded binary decoding and PE validation.
- Added Windows executable-directory resolution, one-file final installation, inherited-pipe handoff, transaction token, mutex gate/successor ownership, and post-exit old-image cleanup.
- Added rollback cleanup for every preparation failure after the final executable is created.
- Prevented the successor from inheriting the old process's redirected standard file handles.
- Added the required process-image query access for the parent validation call.
- Added panel Update controls and intentional reconnect handling.
- Added unit/static contracts, process-level update tests, and a panel-level update test.
- Hardened the Windows Python harness against TCP coalescing, successful-socket closure, incorrect PONG expectations, subprocess pipe/file-handle leaks, mutex-probe false assumptions, unbounded update sends, and test runs without a global deadline.
- Replaced the custom `NtCreateMutant` single-instance path with documented `CreateMutexW` ownership semantics and a global mutex name, eliminating ambiguity during successor takeover.
- Explicitly closed parent-side handoff IPC handles on every preparation/handoff exit path so successor lifetime and EOF are deterministic.
- Added both update tests to the existing Windows GitHub Actions workflow.
- Bounded the real panel reconnect `accept()` used after a successful update so the panel cannot wait indefinitely for a successor.

Verified in this environment:
- Python `compileall` and AST checks for all tools.
- End-to-end `panel.py` Update -> reconnect -> CLOSE test using a synthetic agent peer.
- Python socket framing tests with coalesced and fragmented messages.
- Heartbeat/PONG command-result handling tests.
- Base64 binary payload round-trip tests.
- Static contracts for update APIs, filename/path safety, no update CLI arguments, IPC, mutex handoff, inherited-handle protection, and single-file implementation.
- Clean package inventory and ZIP integrity.
- Fresh ZIP extraction and post-package validation.

Environment limitation:
- This execution environment has no Rust toolchain and no Windows runtime, so `cargo test`, the MSVC build, and the real Windows update process harness cannot be executed locally.
- GitHub Actions is configured to run the Rust test/build plus both Windows update harnesses on `windows-latest`; no remote CI run was available from this session, so CI is configured but not claimed as remotely executed.

Platform note:
- Under the strict single-file/no-staging requirement, the updater rejects an in-place update whose target filename equals the running executable filename. Windows keeps the active executable image mapped/locked; the panel therefore exposes `update-as:<filename>:<path>` for a distinct final successor filename. The old image is removed only after the successor is live.
