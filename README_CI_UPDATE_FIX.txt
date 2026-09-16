ztsec_agent update CI fix

Fixes the Windows CI cargo-test failure caused by a brittle source-contract assertion that depended on whitespace in the Rust ACK expression.

Also keeps the compile-safety fixes required by RUSTFLAGS=-D warnings:
- UpdateHandoff is pub(crate) because spawn_successor is pub(crate).
- removed the unused cleanup_update_artifacts helper.
- getrandom remains pinned to 0.2.17 and uses getrandom::getrandom.
- update hashing uses a heap-backed 64 KiB buffer instead of a 1 MiB stack buffer.

Local verification in the supplied environment:
- pytest tools/panel_test.py tools/test_update_contract.py: 12 passed
- Python syntax compilation: PASS
- update source/static audit: PASS
- no remaining pub(crate) functions returning private update types

Windows cargo/MSVC runtime verification was not possible in this environment.
