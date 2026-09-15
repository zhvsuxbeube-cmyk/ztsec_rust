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
    assert!(main.contains("maybe_run_successor"));
    let update = std::fs::read_to_string("src/update.rs").unwrap();
    assert!(update.contains("--ztsec-update-successor"));
    assert!(update.contains("WAIT_TIMEOUT_MS"));
    assert!(source.contains("ACK:"));
}
