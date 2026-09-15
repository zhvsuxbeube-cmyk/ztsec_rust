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
fn update_contract_is_single_file_and_simple_handoff() {
    let source = std::fs::read_to_string("src/update.rs").unwrap();
    let sys = std::fs::read_to_string("src/sys.rs").unwrap();
    assert!(source.contains("GetModuleFileNameW"));
    assert!(source.contains("stdout(Stdio::piped())"));
    assert!(source.contains("CreateMutexW" ) || sys.contains("CreateMutexW"));
    assert!(source.contains("create_new(true)"));
    assert!(source.contains("release_single"));
    assert!(source.contains("signal_success"));
    assert!(source.contains("spawn()"));
    assert!(source.contains("cmd.exe"));
    for banned in [
        "CreateTemp", "\".tmp\"", "\".bak\"", "\".new\"", "\".old\"",
        "update.flag", "update.json", "promote-", "PeekNamedPipe", "ChildHandoff",
    ] {
        assert!(!source.contains(banned), "unexpected auxiliary update artifact or old handoff mechanism: {banned}");
    }
}
