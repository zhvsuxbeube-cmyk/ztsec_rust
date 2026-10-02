#[test]
fn contract() {
    let source = std::fs::read_to_string("src/text.rs").unwrap();
    for command in [
        "SLEEP", "HIBERNATE", "RESTART", "SHUTDOWN", "RECONNECT", "CLOSE", "EXECUTE", "UPDATE",
    ] {
        assert!(source.contains(command));
    }
    assert!(source.contains("UPDATE_BEGIN:"));
    assert!(source.contains("UPDATE_CHUNK:"));
    assert!(source.contains("UPDATE_END:"));
    assert!(source.contains("HELLO:FINGERPRINT:"));
    assert!(source.contains("DATA:"));
    assert!(source.contains("PLUGIN:"));
    assert!(source.contains("PLUGIN_EVENT:"));
    assert!(source.contains("PLUGIN_OUT:"));
    assert!(source.contains(".Caption -replace '^Microsoft\\s+', ''"));
    assert!(source.contains("){\'Admin\'}else{\'User\'}"));
    assert!(!source.contains("DisplayVersion"));
}

#[test]
fn transport_contract() {
    let source = std::fs::read_to_string("src/transport.rs").unwrap();
    assert!(source.contains("TorClient::create_bootstrapped"));
    assert!(source.contains("tor.connect"));
    assert!(source.contains("client_async_with_config"));
    assert!(source.contains("MAX_WS_MESSAGE_BYTES"));
    assert!(source.contains("match &endpoint"), "Drop-bearing Endpoint must be matched by reference");
    assert!(!source.contains("match endpoint {"), "Drop-bearing Endpoint must not be destructured by value");
    let args = std::fs::read_to_string("src/args.rs").unwrap();
    assert!(args.contains("ZTSEC_ENDPOINT"));
    assert!(args.contains("ZTSEC_AUTH_KEY_FILE"));
}

#[test]
fn update_flow_contract() {
    let source = std::fs::read_to_string("src/net.rs").unwrap();
    let update = std::fs::read_to_string("src/update.rs").unwrap();
    assert!(source.contains("text::UPDATE"));
    assert!(source.contains("UPDATE_BEGIN"));
    assert!(source.contains("UPDATE_CHUNK"));
    assert!(source.contains("UPDATE_END"));
    assert!(source.contains("spawn_blocking(move || handoff.wait_admission())"));
    assert!(!source.contains("unsupported-in-websocket-mode"));
    assert!(update.contains("--ztsec-update-successor"));
    assert!(update.contains("PROBE_WAIT"));
    assert!(update.contains("UPDATE_FINAL_READY:"));
    assert!(update.contains("request_helper_self_delete"));
}

#[test]
fn runtime_stays_multithreaded() {
    let main = std::fs::read_to_string("src/main.rs").unwrap();
    assert!(main.contains("new_multi_thread"));
    assert!(main.contains("worker_threads(2)"));
}
