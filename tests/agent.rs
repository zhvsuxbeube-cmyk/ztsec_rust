#[test]
fn contract() {
    let source = std::fs::read_to_string("src/text.rs").unwrap();
    for command in [
        "SLEEP", "HIBERNATE", "RESTART", "SHUTDOWN", "RECONNECT", "CLOSE", "EXECUTE", "UPDATE",
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
    assert!(source.contains("){'Admin'}else{'User'}"));
    assert!(!source.contains("DisplayVersion"));
}

#[test]
fn update_contract_is_minimal() {
    let source = std::fs::read_to_string("src/update.rs").unwrap();
    let main = std::fs::read_to_string("src/main.rs").unwrap();
    assert!(source.contains("_update"));
    assert!(source.contains("success.txt"));
    assert!(source.contains("failed.txt"));
    assert!(source.contains("create_new(true)"));
    assert!(source.contains("release"));
    assert!(source.contains("acquire"));
    assert!(source.contains("cmd.exe"));
    assert!(source.contains("move /Y"));
    assert!(source.contains("start"));
    assert!(main.contains("update::is_update()"));
    assert!(!source.contains("TcpListener"));
    assert!(!source.contains("BCryptGenRandom"));
    assert!(!source.contains("update-signal"));
    assert!(!source.contains("--update-child"));
    assert!(!source.contains("PeekNamedPipe"));
    assert!(!source.contains("ChildHandoff"));
    assert!(source.contains("fn up_name"));
    assert!(source.contains(r#"format!("{stem}{UPDATE_SUFFIX}{ext}")"#));
}
