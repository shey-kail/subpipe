//! AnyTLS protocol parser

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Helper function to parse boolean values from strings (supports 0/1/true/false)
fn parse_bool(s: &str) -> Option<bool> {
    if s == "1" || s == "true" {
        Some(true)
    } else if s == "0" || s == "false" {
        Some(false)
    } else {
        None
    }
}

/// Helper function to URL decode a string
fn url_decode(s: &str) -> String {
    urlencoding::decode(s)
        .unwrap_or_else(|_| s.to_string().into())
        .to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnyTLSConfig {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub uuid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub insecure: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_insecure: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alpn: Option<String>,
}

impl AnyTLSConfig {
    pub fn parse(url: &str) -> Result<Self> {
        if !url.starts_with("anytls://") {
            bail!("Not a valid AnyTLS URL");
        }

        // Parse anytls://uuid@server:port/?params#name
        let without_scheme = &url[9..];
        let (main_part, fragment) = if let Some(idx) = without_scheme.find('#') {
            (&without_scheme[..idx], Some(&without_scheme[idx + 1..]))
        } else {
            (without_scheme, None)
        };

        let (uuid_server_port, query_part) = if let Some(idx) = main_part.find('?') {
            (&main_part[..idx], Some(&main_part[idx + 1..]))
        } else {
            (main_part, None)
        };

        let uuid_host_port: Vec<&str> = uuid_server_port.splitn(2, '@').collect();
        if uuid_host_port.len() != 2 {
            bail!("Invalid AnyTLS URL format");
        }

        let uuid = uuid_host_port[0].to_string();

        // Extract host:port from the string (before any path/query)
        let host_port_str = uuid_host_port[1].splitn(2, '/').next().unwrap_or(uuid_host_port[1]);
        let host_port: Vec<&str> = host_port_str.rsplitn(2, ':').collect();
        if host_port.len() != 2 {
            bail!("Invalid host:port format");
        }

        let server = host_port[1].to_string();
        let port_str = host_port[0].trim_end_matches(|c: char| !c.is_ascii_digit());
        let port = port_str.parse::<u16>()?;

        // Parse query parameters
        let mut params = HashMap::new();
        if let Some(query) = query_part {
            for pair in query.split('&') {
                if pair.is_empty() {
                    continue;
                }
                let kv: Vec<&str> = pair.splitn(2, '=').collect();
                if kv.len() == 2 {
                    params.insert(kv[0].to_string(), kv[1].to_string());
                }
            }
        }

        let name = fragment
            .map(url_decode)
            .unwrap_or_else(|| "AnyTLS".to_string());

        let security = params.get("security").map(|s| url_decode(s));
        let sni = params.get("sni").map(|s| url_decode(s));
        let fp = params.get("fp").map(|s| url_decode(s));
        let alpn = params.get("alpn").map(|s| url_decode(s));
        let insecure = params.get("insecure").and_then(|s| parse_bool(s));
        // allowInsecure may also be present
        let allow_insecure = params.get("allowInsecure").and_then(|s| parse_bool(s));

        Ok(AnyTLSConfig {
            name,
            server,
            port,
            uuid,
            security,
            sni,
            fp,
            insecure,
            allow_insecure: allow_insecure.or(insecure),
            alpn,
        })
    }

    pub fn to_singbox(&self) -> serde_json::Value {
        let mut outbound = serde_json::json!({
            "type": "anytls",
            "tag": self.name,
            "server": self.server,
            "server_port": self.port,
            "password": self.uuid,
        });

        // TLS config
        let mut tls_config = serde_json::json!({
            "enabled": true
        });

        if let Some(ref sni) = self.sni {
            tls_config["server_name"] = serde_json::json!(sni);
        }

        if let Some(insecure) = self.insecure.or(self.allow_insecure) {
            tls_config["insecure"] = serde_json::json!(insecure);
        }

        if let Some(ref fp) = self.fp {
            tls_config["utls"] = serde_json::json!({
                "enabled": true,
                "fingerprint": fp
            });
        }

        if let Some(ref alpn) = self.alpn {
            // AnyTLS uses h2,http/1.1 as ALPN
            if alpn.contains(',') {
                tls_config["alpn"] = serde_json::json!(alpn.split(',').collect::<Vec<&str>>());
            } else {
                tls_config["alpn"] = serde_json::json!([alpn]);
            }
        } else {
            // Default ALPN for AnyTLS
            tls_config["alpn"] = serde_json::json!(["h2", "http/1.1"]);
        }

        outbound["tls"] = tls_config;

        outbound
    }

    pub fn to_clash(&self) -> serde_yaml::Value {
        let mut proxy = serde_yaml::Mapping::new();
        proxy.insert(
            serde_yaml::Value::String("name".to_string()),
            serde_yaml::Value::String(self.name.clone())
        );
        proxy.insert(
            serde_yaml::Value::String("type".to_string()),
            serde_yaml::Value::String("anytls".to_string())
        );
        proxy.insert(
            serde_yaml::Value::String("server".to_string()),
            serde_yaml::Value::String(self.server.clone())
        );
        proxy.insert(
            serde_yaml::Value::String("port".to_string()),
            serde_yaml::Value::Number(self.port.into())
        );
        proxy.insert(
            serde_yaml::Value::String("uuid".to_string()),
            serde_yaml::Value::String(self.uuid.clone())
        );
        proxy.insert(
            serde_yaml::Value::String("password".to_string()),
            serde_yaml::Value::String(self.uuid.clone())
        );

        if let Some(ref sni) = self.sni {
            proxy.insert(
                serde_yaml::Value::String("sni".to_string()),
                serde_yaml::Value::String(sni.clone())
            );
        }

        if let Some(ref fp) = self.fp {
            proxy.insert(
                serde_yaml::Value::String("client-fingerprint".to_string()),
                serde_yaml::Value::String(fp.clone())
            );
        }

        if let Some(insecure) = self.insecure.or(self.allow_insecure) {
            proxy.insert(
                serde_yaml::Value::String("skip-cert-verify".to_string()),
                serde_yaml::Value::Bool(insecure)
            );
        }

        if let Some(ref alpn) = self.alpn {
            proxy.insert(
                serde_yaml::Value::String("alpn".to_string()),
                serde_yaml::Value::String(alpn.clone())
            );
        }

        serde_yaml::Value::Mapping(proxy)
    }
}
