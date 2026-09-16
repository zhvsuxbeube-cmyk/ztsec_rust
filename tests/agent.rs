#[test]
fn contract() {
    let source = std::fs::read_to_string("src/text.rs").unwrap();
    for command in [
        "SLEEP",
        "HIBERNATE",
        "RESTART",
        "SHUTDOWN",
        "RECONNECT",
        "CLOSE",
        "EXECUTE",
        "UPDATE",
    ] {
        assert!(source.contains(command));
    }
    assert!(!source.contains("CMD:BLOCK"));
    assert!(source.contains("127.0.0.1"));
    assert!(source.contains("4793"));
    assert!(source.contains("HELLO:FINGERPRINT:"));
    assert!(source.contains("DATA:"));
    assert!(source.contains("PLUGIN:"));
    assert!(source.contains("PLUGIN_EVENT:"));
    assert!(source.contains("PLUGIN_OUT:"));
    assert!(source.contains(".Caption -replace '^Microsoft\\s+', ''"));
    assert!(source.contains("){'Admin'}else{'User'}"));
    assert!(!source.contains("DisplayVersion"));
}


#[test]
fn update_flow_contract() {
    let source = std::fs::read_to_string("src/net.rs").unwrap();
    assert!(source.contains("CMD:UPDATE") || source.contains("text::UPDATE"));
    assert!(source.contains("stage_bytes"));
    assert!(source.contains("spawn_successor"));
    assert!(source.contains("sha256_hex"));
    let main = std::fs::read_to_string("src/main.rs").unwrap();
    let update = std::fs::read_to_string("src/update.rs").unwrap();
    assert!(main.contains("maybe_run_successor"));
    assert!(update.contains("--ztsec-update-successor"));
    assert!(update.contains("PROBE_WAIT"));
    assert!(update.contains("--ztsec-update-agent-arg="));
    assert!(update.contains("helper"));
    assert!(source.contains("text::ACK"));
    assert!(source.contains("text::UPDATE"));
    assert!(source.contains("text::ACK, text::UPDATE"));
    assert!(source.contains("starts_with_ascii_ci(raw, text::UPDATE)"));
    assert!(source.contains(r#"send(stream, &format!("{}{}", text::ACK, text::UPDATE))"#));
    assert!(!source.contains("std::process::exit(0);"));
    assert!(source.contains("update successor launch failed"));
    assert!(source.contains("update staging failed"));
    assert!(source.contains("update acknowledgement send failed"));
    assert!(source.contains("handoff.wait_admission"));
    assert!(source.contains("spawn_probe"));
    assert!(update.contains("HELLO:UPDATE-PROBE:"));
    assert!(update.contains("ACK:UPDATE-PROBE:"));
    assert!(update.contains("UPDATE_PROBE_READY:"));
    assert!(update.contains("ACK:UPDATE_PROBE_READY:"));
    assert!(update.contains("updated agent probe timed out"));
    assert!(update.contains("child.kill"));
    assert!(update.contains("let mut buffer = vec![0u8; 64 * 1024]"));
    assert!(!update.contains("let mut buf = [0u8; 1024 * 1024]"));
    assert!(update.contains("replace_file(&backup, target)"));
    assert!(update.contains("restart_original_after_failure"));
    assert!(update.contains("staged update changed before parent shutdown"));
    assert!(update.contains("updated agent probe timed out"));
}

#[test]
fn update_probe_server_contract() {
    let update = std::fs::read_to_string("src/update.rs").unwrap();
    assert!(update.contains("HELLO:UPDATE-PROBE:"));
    assert!(update.contains("ACK:UPDATE-PROBE:"));
    assert!(update.contains("UPDATE_PROBE_READY:"));
    assert!(update.contains("ACK:UPDATE_PROBE_READY:"));
    assert!(update.contains("notify_handoff_failure"));
    assert!(update.contains("probe_child" ) || update.contains("spawn_probe"));
}
