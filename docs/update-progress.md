# Update flow

The Windows update path is intentionally minimal.

1. The running agent receives only update bytes; it derives `<current-name>_update.exe` from its own executable name and checks the derived path is a single safe filename.
2. `success.txt` and `failed.txt` are cleared, the agent releases its mutex, and starts the update executable.
3. The original waits up to 60 seconds for an empty marker file.
4. The update executable detects `_update` from its own filename before normal startup, acquires the mutex, connects to the panel, and checks that the non-`_update` executable exists beside it.
6. It schedules `cmd.exe` to wait briefly, rename `<current-name>_update.exe` back to `<current-name>.exe`, and start it. It then writes `success.txt`.
7. If the update executable cannot connect, cannot find the original, or cannot schedule the rename, it writes `failed.txt` and exits.
8. On `failed.txt` or timeout, the original terminates the update process, removes the staged executable, reacquires the mutex, reconnects to the panel, and sends `ERR:UPDATE:FAILED`.

No child arguments, inherited pipes, TCP handoff listeners, tokens, or temporary promotion files are used.
