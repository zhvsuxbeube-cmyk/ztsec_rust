ztsec_agent update/CI reliability notes

The update implementation uses a fail-closed, multi-phase handoff:
- validate the received hash and payload before staging;
- durably stage and re-hash the update using a heap-backed 64 KiB buffer;
- run the staged executable in isolated probe mode;
- require server probe acknowledgement and a local old-agent admission handshake;
- acknowledge the panel only after candidate admission succeeds;
- after the original process exits, replace the original executable path/name;
- launch the installed image and require final normal-mode connection proof from the new image;
- if final readiness fails, terminate the candidate, restore the original image, and restart it.

The update helper is scheduled for self-cleanup after it exits. Internal final-readiness
arguments are ignored by the normal command-line parser, so the new image still receives
the original --ip/--port configuration.

The CI update harness accepts the expected concurrent probe connection and verifies the
final normal-mode reconnection separately from the original connection.
