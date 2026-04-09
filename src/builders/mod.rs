//! Builders module - generates configurations for different clients

use crate::parsers::ProxyConfig;
use serde_json::Value as JsonValue;
use serde_yaml::Value as YamlValue;

/// Build a simple Clash config with only proxy nodes and a simple selector
pub fn build_simple_clash(proxies: &[ProxyConfig]) -> YamlValue {
    use serde_yaml::Value;

    let mut proxy_list: Vec<YamlValue> = Vec::new();
    for proxy in proxies {
        proxy_list.push(proxy.to_clash());
    }

    let mut proxy_names: Vec<YamlValue> = Vec::new();
    for proxy in proxies {
        proxy_names.push(YamlValue::String(proxy.name().to_string()));
    }

    // Build proxy groups
    let mut proxy_groups: Vec<YamlValue> = Vec::new();

    // Main selector group
    let mut proxy_group = serde_yaml::Mapping::new();
    proxy_group.insert(
        Value::String("name".to_string()),
        Value::String("Proxy".to_string())
    );
    proxy_group.insert(
        Value::String("type".to_string()),
        Value::String("selector".to_string())
    );

    let mut group_proxies: Vec<YamlValue> = vec![
        Value::String("DIRECT".to_string()),
        Value::String("REJECT".to_string()),
    ];
    group_proxies.extend(proxy_names.clone());
    proxy_group.insert(
        Value::String("proxies".to_string()),
        Value::Sequence(group_proxies)
    );
    proxy_groups.push(Value::Mapping(proxy_group));

    // Build config
    let mut config = serde_yaml::Mapping::new();
    config.insert(Value::String("port".to_string()), Value::Number(7890.into()));
    config.insert(Value::String("socks-port".to_string()), Value::Number(7891.into()));
    config.insert(Value::String("allow-lan".to_string()), Value::Bool(false));
    config.insert(Value::String("mode".to_string()), Value::String("rule".to_string()));
    config.insert(Value::String("log-level".to_string()), Value::String("info".to_string()));
    config.insert(Value::String("proxies".to_string()), Value::Sequence(proxy_list));
    config.insert(Value::String("proxy-groups".to_string()), Value::Sequence(proxy_groups));

    // Simple rules: DNS direct, then everything through Proxy
    let rules: Vec<YamlValue> = vec![
        Value::String("PROTOCOL,DNS,DIRECT".to_string()),
        Value::String("MATCH,Proxy".to_string()),
    ];
    config.insert(Value::String("rules".to_string()), Value::Sequence(rules));

    Value::Mapping(config)
}

/// Build a simple Singbox config with only proxy nodes and a simple selector
pub fn build_simple_singbox(proxies: &[ProxyConfig]) -> JsonValue {
    use serde_json::json;

    let mut outbounds = Vec::new();

    // Add basic outbounds
    outbounds.push(json!({"type": "block", "tag": "REJECT"}));
    outbounds.push(json!({"type": "direct", "tag": "DIRECT"}));

    // Add proxy outbounds
    let mut proxy_names = Vec::new();
    for proxy in proxies {
        let mut singbox_proxy = proxy.to_singbox();
        // Ensure tag is set
        if let Some(obj) = singbox_proxy.as_object_mut() {
            if !obj.contains_key("tag") {
                obj.insert("tag".to_string(), json!(proxy.name()));
            }
        }
        outbounds.push(singbox_proxy);
        proxy_names.push(proxy.name().to_string());
    }

    // Add selector group
    let mut selector_outbounds = vec!["DIRECT".to_string(), "REJECT".to_string()];
    selector_outbounds.extend(proxy_names);

    outbounds.push(json!({
        "type": "selector",
        "tag": "Proxy",
        "outbounds": selector_outbounds
    }));

    json!({
        "log": {
            "level": "info"
        },
        "inbounds": [
            { "type": "mixed", "tag": "mixed-in", "listen": "0.0.0.0", "listen_port": 2080 }
        ],
        "outbounds": outbounds,
        "route": {
            "rules": [
                { "protocol": "dns", "action": "hijack-dns" },
                { "outbound": " Proxy" },
                { "outbound": "REJECT" }
            ],
            "final": "Proxy"
        }
    })
}

/// Build a simple Surge config with only proxy nodes and a simple selector
pub fn build_simple_surge(proxies: &[ProxyConfig]) -> String {
    let mut result = String::new();

    // General section
    result.push_str("[General]\n");
    result.push_str("loglevel = notify\n");
    result.push_str("dns-server = 223.5.5.5, 114.114.114.114\n");
    result.push_str("allow-wifi-access = false\n");
    result.push_str("skip-proxy = 127.0.0.1, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, localhost, *.local\n");
    result.push_str("ipv6 = false\n");
    result.push_str("test-timeout = 5\n");
    result.push_str("proxy-test-url = http://www.gstatic.com/generate_204\n");
    result.push('\n');

    // Proxy section
    result.push_str("[Proxy]\n");
    for proxy in proxies {
        let line = surge_proxy_line(proxy);
        result.push_str(&line);
        result.push('\n');
    }
    result.push('\n');

    // Proxy Group section
    result.push_str("[Proxy Group]\n");

    let proxy_list: Vec<String> = proxies.iter().map(|p| p.name().to_string()).collect();
    let proxy_str = proxy_list.join(", ");

    result.push_str(&format!("Proxy = selector, DIRECT, REJECT, {}\n", proxy_str));
    result.push('\n');

    // Rules section
    result.push_str("[Rule]\n");
    result.push_str("PROTOCOL,DNS,DIRECT\n");
    result.push_str("MATCH,Proxy\n");

    result
}

/// Convert a proxy to Surge format line
pub fn surge_proxy_line(proxy: &ProxyConfig) -> String {
    match proxy {
        ProxyConfig::ShadowSocks(ss) => {
            let mut params = Vec::new();
            params.push(format!("encrypt-method={}", ss.method));
            params.push(format!("password={}", ss.password));

            format!(
                "{} = ss, {}, {}, {}",
                ss.name, ss.server, ss.port, params.join(", ")
            )
        }
        ProxyConfig::VMess(vmess) => {
            let mut params = Vec::new();
            params.push(format!("username={}", vmess.uuid));
            params.push(format!("encrypt-method={}", vmess.security));

            if vmess.tls.as_deref() == Some("tls") {
                params.push(format!("tls=true"));
                if let Some(ref sni) = vmess.sni {
                    params.push(format!("sni={}", sni));
                }
            }

            params.push(format!("network={}", vmess.network));

            if vmess.network == "ws" {
                if let Some(ref path) = vmess.path {
                    params.push(format!("ws-path={}", path));
                }
                if let Some(ref host) = vmess.host {
                    params.push(format!("ws-headers=Host:{{{}}}", host));
                }
            }

            format!(
                "{} = vmess, {}, {}, {}",
                vmess.name, vmess.server, vmess.port, params.join(", ")
            )
        }
        ProxyConfig::Trojan(trojan) => {
            let mut params = Vec::new();
            params.push(format!("password={}", trojan.password));

            if let Some(ref sni) = trojan.sni {
                params.push(format!("sni={}", sni));
            }

            if let Some(ref alpn) = trojan.alpn {
                params.push(format!("alpn={}", alpn));
            }

            if let Some(insecure) = trojan.insecure {
                params.push(format!("insecure={}", insecure));
            }

            if let Some(ref network) = trojan.network {
                params.push(format!("network={}", network));
                if network == "ws" {
                    if let Some(ref path) = trojan.path {
                        params.push(format!("ws-path={}", path));
                    }
                    if let Some(ref host) = trojan.host {
                        params.push(format!("ws-headers=Host:{{{}}}", host));
                    }
                } else if network == "grpc" {
                    if let Some(ref path) = trojan.path {
                        params.push(format!("grpc-service-name={}", path));
                    }
                }
            }

            format!(
                "{} = trojan, {}, {}, {}",
                trojan.name, trojan.server, trojan.port, params.join(", ")
            )
        }
        ProxyConfig::Hysteria2(hy2) => {
            let mut params = Vec::new();
            params.push(format!("password={}", hy2.password));

            if let Some(ref obfs) = hy2.obfs {
                params.push(format!("obfs={}", obfs));
            }

            if let Some(ref obfs_password) = hy2.obfs_password {
                params.push(format!("obfs-password={}", obfs_password));
            }

            if let Some(ref sni) = hy2.sni {
                params.push(format!("sni={}", sni));
            }

            if let Some(insecure) = hy2.insecure {
                params.push(format!("insecure={}", insecure));
            }

            if let Some(ref alpn) = hy2.alpn {
                params.push(format!("alpn={}", alpn));
            }

            format!(
                "{} = hysteria2, {}, {}, {}",
                hy2.name, hy2.server, hy2.port, params.join(", ")
            )
        }
        ProxyConfig::VLESS(vless) => {
            let mut params = Vec::new();
            params.push(format!("username={}", vless.uuid));

            if !vless.flow.is_empty() {
                params.push(format!("flow={}", vless.flow));
            }

            if let Some(ref network) = vless.network {
                params.push(format!("network={}", network));
            }

            if let Some(ref sni) = vless.sni {
                params.push(format!("sni={}", sni));
            }

            if let Some(ref host) = vless.host {
                params.push(format!("host={}", host));
            }

            if let Some(ref fp) = vless.fp {
                params.push(format!("tls-fingerprint={}", fp));
            }

            if let Some(ref alpn) = vless.alpn {
                params.push(format!("alpn={}", alpn));
            }

            if let Some(ref pbk) = vless.pbk {
                params.push(format!("pbk={}", pbk));
            }

            if let Some(ref sid) = vless.sid {
                params.push(format!("short-id={}", sid));
            }

            format!(
                "{} = vless, {}, {}, {}",
                vless.name, vless.server, vless.port, params.join(", ")
            )
        }
        ProxyConfig::TUIC(tuic) => {
            let mut params = Vec::new();
            params.push(format!("uuid={}", tuic.uuid));
            params.push(format!("password={}", tuic.password));

            if let Some(ref congestion) = tuic.congestion {
                params.push(format!("congestion-control={}", congestion));
            }

            if let Some(ref udp_relay_mode) = tuic.udp_relay_mode {
                params.push(format!("udp-relay-mode={}", udp_relay_mode));
            }

            if let Some(ref sni) = tuic.sni {
                params.push(format!("sni={}", sni));
            }

            if let Some(ref alpn) = tuic.alpn {
                params.push(format!("alpn={}", alpn));
            }

            if let Some(disable_sni) = tuic.disable_sni {
                params.push(format!("disable-sni={}", disable_sni));
            }

            if let Some(zero_rtt) = tuic.zero_rtt_handshake {
                params.push(format!("zero-rtt-handshake={}", zero_rtt));
            }

            format!(
                "{} = tuic, {}, {}, {}",
                tuic.name, tuic.server, tuic.port, params.join(", ")
            )
        }
        _ => {
            // For unsupported types, create a comment
            format!("# {} (unsupported)", proxy.name())
        }
    }
}
