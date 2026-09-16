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
    assert!(net.contains("PLUGIN_OUT:"));
    assert!(net.contains("event_one(plugin_id.trim(), event, data)"));
    let plugin = std::fs::read_to_string("src/plugin.rs").unwrap();
    assert!(plugin.contains("fn safe_transfer_component"));
    assert!(plugin.contains("path traversal") || plugin.contains("invalid plugin transfer id"));
}


#[test]
fn finish_transfer_ends_immutable_borrow_before_load():
    let source = std::fs::read_to_string("src/plugin.rs").unwrap();
    let start = source.find("pub fn finish_transfer").expect("finish_transfer missing");
    let end = source[start..].find("pub fn resume_transfer").map(|o| start + o).unwrap();
    let body = &source[start..end];
    assert!(body.contains("let (id, path, size, hash, received) = {"));
    let load_pos = body.find("self.load(&id, &bytes, host)?;").expect("self.load missing");
    assert!(body.find("let tr = self.transfers.get(transfer_id)").unwrap() < body.find("let (id, path, size, hash, received) = {").unwrap());
    assert!(load_pos > body.find("};
            if received != size").unwrap());
}
