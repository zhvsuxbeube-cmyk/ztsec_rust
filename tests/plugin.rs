#[test]
fn abi_contract() {
    let h = std::fs::read_to_string("plugin/ztsec_plugin.h").unwrap();
    for s in ["PluginOnLoad", "PluginOnEvent", "PluginOnUnload", "zt_emit"] {
        assert!(h.contains(s));
    }
    for s in ["ZT_EVENT_FILE_SEND_BEGIN", "ZT_EVENT_FILE_SEND_CHUNK", "ZT_EVENT_FILE_SEND_END"] {
        assert!(h.contains(s));
    }
    let c = std::fs::read_to_string("plugin/hello.cpp").unwrap();
    let first = c.lines().next().unwrap_or("");
    assert!(first.contains("cl") && first.contains("/LD") && first.contains("hello.cpp"));
    for s in ["Hello from ztsec agent", "PluginOnLoad", "PluginOnEvent", "PluginOnUnload"] {
        assert!(c.contains(s));
    }
}

#[test]
fn plugin_protocol_contract() {
    let text = std::fs::read_to_string("src/text.rs").unwrap();
    for s in ["PLUGIN_MSG:", "PLUGIN_BEGIN:", "PLUGIN_CHUNK:", "PLUGIN_END:", "PLUGIN_RESUME:"] {
        assert!(text.contains(s), "missing {s}");
    }
    let net = std::fs::read_to_string("src/net.rs").unwrap();
    for s in ["plugins.begin_transfer", "plugins.append_transfer", "plugins.finish_transfer", "plugins.resume_transfer"] {
        assert!(net.contains(s), "missing {s}");
    }
    assert!(text.contains("PLUGIN_OUT:"), "missing plugin output protocol token");
    assert!(net.contains("text::PLUGOUT"), "network layer does not emit the plugin output token");
}
