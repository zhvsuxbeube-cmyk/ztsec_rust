from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NET = (ROOT / "src" / "net.rs").read_text(encoding="utf-8")
UPDATE = (ROOT / "src" / "update.rs").read_text(encoding="utf-8")
MAIN = (ROOT / "src" / "main.rs").read_text(encoding="utf-8")


def test_update_is_not_acknowledged_before_candidate_admission():
    admitted = NET.index("handoff.wait_admission()")
    ack = NET.index("text::ACK,text::UPDATE")
    assert admitted < ack


def test_candidate_proves_server_acceptance_and_old_helper_acceptance():
    assert 'HELLO:UPDATE-PROBE:' in UPDATE
    assert 'ACK:UPDATE-PROBE:' in UPDATE
    assert 'UPDATE_PROBE_READY:' in UPDATE
    assert 'ACK:UPDATE_PROBE_READY:' in UPDATE
    assert 'child.kill' in UPDATE
    assert 'updated agent probe timed out' in UPDATE


def test_probe_failure_does_not_promote_candidate():
    run = UPDATE.index('fn run_successor')
    failure = UPDATE.index('notify_handoff_failure', run)
    promotion = UPDATE.index('replace_and_launch(&successor)', run)
    assert failure < promotion


def test_update_candidate_mode_precedes_single_instance_mutex():
    assert MAIN.index('maybe_run_probe') < MAIN.index('sys::single()')


def test_hashing_buffer_is_heap_allocated():
    assert 'let mut buffer = vec![0u8; 64 * 1024];' in UPDATE


def test_post_parent_failure_attempts_original_restart():
    assert 'fn restart_original_after_failure' in UPDATE
    assert 'restart_original_after_failure(' in UPDATE
    assert 'updated agent launch failed' in UPDATE


def test_successor_receives_server_port_and_wait_admission_is_visible():
    source = Path(__file__).resolve().parents[1] / "src" / "net.rs"
    text = source.read_text(encoding="utf-8")
    assert 'session(&mut stream, ip, port, &fp, &host, &mut plugins)' in text
    assert 'fn session(stream: &mut TcpStream, ip: &str, port: u16' in text

    update = Path(__file__).resolve().parents[1] / "src" / "update.rs"
    update_text = update.read_text(encoding="utf-8")
    assert 'pub(crate) fn wait_admission(self)' in update_text
    assert 'getrandom::getrandom(&mut bytes)' in update_text


def test_successor_setup_cleans_helper_on_prelaunch_failures():
    update = Path(__file__).resolve().parents[1] / "src" / "update.rs"
    text = update.read_text(encoding="utf-8")
    section = text[text.index("pub(crate) fn spawn_successor"):text.index("pub(crate) fn maybe_run_probe")]
    assert 'let _ = fs::remove_file(&helper);' in section
    assert 'if let Err(error) = command.spawn()' in section


def test_getrandom_api_matches_pinned_version():
    cargo = Path(__file__).resolve().parents[1] / "Cargo.toml"
    cargo_text = cargo.read_text(encoding="utf-8")
    update = Path(__file__).resolve().parents[1] / "src" / "update.rs"
    update_text = update.read_text(encoding="utf-8")
    assert 'getrandom = "=0.2.17"' in cargo_text
    assert 'getrandom::getrandom(&mut bytes)' in update_text
    assert 'getrandom::fill(&mut bytes)' not in update_text
