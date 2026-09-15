# Update implementation checkpoint

Current phase: handoff regression fix and final source verification

Changes in this revision:

- Traced the Windows update failure to the successor's `stdout` being connected to a parent-owned pipe. The parent consumed `SUCCESS`, exited after a successful handoff, and thereby closed the pipe while the still-running successor continued to print. On Windows this produced `The pipe is being closed` and the successor then reset the panel TCP connection.
- Replaced the parent/child success channel with a loopback TCP control socket bound to `127.0.0.1` on an ephemeral port.
- Added a fresh 128-bit token from Windows `BCryptGenRandom`; the successor must return `SUCCESS:<token>` to the loopback listener before the parent commits the update.
- Detached successor stdout with `Stdio::null()` so successor lifetime is no longer coupled to the old process or CI's redirected output handles.
- Kept the existing mutex takeover, successor reconnect, rollback, one-file installation, PE validation, and old-image cleanup behavior intact.
- Updated argument parsing, Windows child startup, network startup, and the static update contract to carry and verify the new handoff signal parameters.

Verification performed in this environment:

- Python AST parsing for all checked-in Python tooling: passed.
- Repository-wide structural and handoff invariants: passed.
- Confirmed no generated Python cache artifacts remain in the packaged source tree.
- Confirmed the repaired source no longer contains the old `stdout(Stdio::piped())` handoff or `io::stdout()` success signal, and contains the new loopback listener, token, and detached successor stdout path.
- Confirmed the archive can be created and re-extracted with the complete source tree intact.

Environment limitation:

- This execution environment does not contain `cargo`, `rustc`, `rustfmt`, or a Windows runtime/MSVC toolchain. Therefore the Rust unit tests, Windows MSVC build, and the real Windows `tools/update_test.py` process handoff test could not be executed locally in this session.
- The repository's GitHub Actions workflow remains the authoritative Windows build/test path and already includes the update process and panel handoff tests. No remote CI run was available to claim as executed from this session.
