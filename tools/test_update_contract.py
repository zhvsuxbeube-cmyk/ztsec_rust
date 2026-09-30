from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NET = (ROOT / "src" / "net.rs").read_text(encoding="utf-8")
UPDATE = (ROOT / "src" / "update.rs").read_text(encoding="utf-8")
MAIN = (ROOT / "src" / "main.rs").read_text(encoding="utf-8")
ARGS = (ROOT / "src" / "args.rs").read_text(encoding="utf-8")
TRANSPORT = (ROOT / "src" / "transport.rs").read_text(encoding="utf-8")


def test_update_is_not_acknowledged_before_candidate_admission():
    normalized = "".join(NET.split())
    assert "spawn_blocking(move || handoff.wait_admission())" in normalized
    assert "text::ACK" in NET and "text::UPDATE" in NET


def test_candidate_proves_server_acceptance_and_old_helper_acceptance():
    for marker in (
        "HELLO:UPDATE-PROBE:", "ACK:UPDATE-PROBE:", "UPDATE_PROBE_READY:",
        "ACK:UPDATE_PROBE_READY:", "child.kill", "updated agent probe timed out",
    ):
        assert marker in UPDATE


def test_probe_failure_does_not_promote_candidate():
    run = UPDATE.index("fn run_successor")
    failure = UPDATE.index("notify_handoff_failure", run)
    promotion = UPDATE.index("replace_and_launch(&successor)", run)
    assert failure < promotion


def test_update_candidate_mode_precedes_single_instance_mutex():
    assert MAIN.index("maybe_run_probe") < MAIN.index("sys::single")


def test_hashing_buffer_is_heap_allocated():
    assert "let mut buffer = vec![0u8; 64 * 1024];" in UPDATE


def test_post_parent_failure_attempts_original_restart():
    for marker in (
        "fn restart_original_after_failure", "restart_original_after_failure(",
        "final readiness timed out", "original-agent restart failed",
    ):
        assert marker in UPDATE


def test_websocket_update_transfer_is_bounded_and_chunked():
    for marker in ("UPDATE_BEGIN", "UPDATE_CHUNK", "UPDATE_END", "128 * 1024", "max_update_bytes"):
        assert marker in NET
    assert "unsupported-in-websocket-mode" not in NET


def test_agent_transport_is_embedded_arti():
    assert "TorClient::create_bootstrapped" in TRANSPORT
    assert "tor.connect" in TRANSPORT
    assert "client_async_with_config" in TRANSPORT
    assert "std::process::Command" not in TRANSPORT


def test_agent_configuration_exposes_onion_endpoint_and_auth():
    assert "ZTSEC_ENDPOINT" in ARGS
    assert "--endpoint" in ARGS
    assert "ZTSEC_AUTH_KEY_FILE" in ARGS
    assert "--arti-state-dir" in ARGS
    assert "--arti-cache-dir" in ARGS


def test_successor_setup_cleans_helper_on_prelaunch_failures():
    text = UPDATE[UPDATE.index("pub(crate) fn spawn_successor") : UPDATE.index("pub(crate) fn maybe_run_probe")]
    assert "let _ = fs::remove_file(&helper);" in text
    assert "if let Err(error) = command.spawn()" in text


def test_getrandom_api_matches_pinned_version():
    cargo = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    assert 'getrandom = "=0.2.17"' in cargo
    assert "getrandom::getrandom(&mut bytes)" in UPDATE
    assert "getrandom::fill(&mut bytes)" not in UPDATE
