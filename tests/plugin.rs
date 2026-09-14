#[test]
fn abi_contract() {
    let h = std::fs::read_to_string("plugin/ztsec_plugin.h").unwrap();
    for s in ["PluginOnLoad", "PluginOnEvent", "PluginOnUnload", "zt_emit"] {
        assert!(h.contains(s));
    }
    let c = std::fs::read_to_string("plugin/hello.cpp").unwrap();
    let first = c.lines().next().unwrap_or("");
    assert!(
        first.contains("cl") && first.contains("/LD") && first.contains("hello.cpp"),
        "first line must be cl compile command, got: {first}"
    );
    for s in ["Hello from ztsec agent", "PluginOnLoad", "PluginOnEvent", "PluginOnUnload"] {
        assert!(c.contains(s));
    }
}
