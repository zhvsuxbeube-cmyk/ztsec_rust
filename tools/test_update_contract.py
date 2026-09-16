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
