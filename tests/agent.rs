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
fn update_contract_is_no_argument_and_single_file() {
    let source = std::fs::read_to_string("src/update.rs").unwrap();
    let sys = std::fs::read_to_string("src/sys.rs").unwrap();
    assert!(source.contains("GetModuleFileNameW"));
    assert!(source.contains("stdout(Stdio::piped())"));
    assert!(sys.contains("CreateMutexW"));
    assert!(source.contains("BCryptGenRandom"));
    assert!(source.contains("create_new(true)"));
    assert!(!source.contains(".args(") && !source.contains(".arg("));
    for banned in ["CreateTemp", "\".tmp\"", "\".bak\"", "\".new\"", "\".old\"", "update.flag", "update.json", "promote-", "cmd.exe"] {
        assert!(!source.contains(banned), "unexpected auxiliary update artifact or shell path: {banned}");
    }
}
