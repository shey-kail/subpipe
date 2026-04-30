//! TUIC protocol parser

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use urlencoding;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TUICConfig {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub uuid: String,
    pub password: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub congestion: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udp_relay_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alpn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable_sni: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zero_rtt_handshake: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_insecure: Option<bool>,
}

impl TUICConfig {
    pub fn parse(url: &str) -> Result<Self> {
        if !url.starts_with("tuic://") {
            bail!("Not a valid TUIC URL");
        }

        // Parse tuic://uuid:password@server:port?params#name
        let without_scheme = &url[7..];
        let (main_part, fragment) = if without_scheme.contains('#') {
            let parts: Vec<&str> = without_scheme.splitn(2, '#').collect();
            (parts[0], Some(parts[1]))
        } else {
            (without_scheme, None)
        };

        let (uuid_password_server_port, query_part) = if main_part.contains('?') {
            let parts: Vec<&str> = main_part.splitn(2, '?').collect();
            (parts[0], Some(parts[1]))
        } else {
            (main_part, None)
        };

        let uuid_password_host_port: Vec<&str> = uuid_password_server_port.splitn(2, '@').collect();
        if uuid_password_host_port.len() != 2 {
            bail!("Invalid TUIC URL format");
        }

        let uuid_password: Vec<&str> = uuid_password_host_port[0].splitn(2, ':').collect();
        if uuid_password.len() != 2 {
            bail!("Invalid uuid:password format");
        }

        let uuid = uuid_password[0].to_string();
        let password = urlencoding::decode(uuid_password[1])
            .unwrap_or_else(|_| uuid_password[1].to_string().into())
            .to_string();
        
        let host_port: Vec<&str> = uuid_password_host_port[1].rsplitn(2, ':').collect();
        if host_port.len() != 2 {
            bail!("Invalid host:port format");
        }

        let server = host_port[1].to_string();
        let port = host_port[0].parse::<u16>()?;

        // Parse query parameters
        let mut params = HashMap::new();
        if let Some(query) = query_part {
            for pair in query.split('&') {
                let kv: Vec<&str> = pair.splitn(2, '=').collect();
                if kv.len() == 2 {
                    params.insert(kv[0].to_string(), kv[1].to_string());
                }
            }
        }

        let name = fragment
            .as_ref()
            .map(|n| urlencoding::decode(n).unwrap_or_else(|_| n.to_string().into()).to_string())
            .unwrap_or_else(|| "TUIC".to_string());
        let congestion = params.get("congestion_control").map(|s| s.as_str()).map(|s| s.to_string());
        let udp_relay_mode = params.get("udp_relay_mode").map(|s| s.as_str()).map(|s| s.to_string());
        let sni = params.get("sni").map(|s| s.as_str()).map(|s| s.to_string());
        let alpn = params.get("alpn").map(|s| s.as_str()).map(|s| s.to_string());
        let disable_sni = params.get("disable_sni").and_then(|s| s.parse::<bool>().ok());
        let zero_rtt_handshake = params.get("zero_rtt_handshake").and_then(|s| s.parse::<bool>().ok());
        let allow_insecure = params.get("allow_insecure").or_else(|| params.get("allowInsecure"))
            .and_then(|s| {
                if s == "1" || s == "true" {
                    Some(true)
                } else if s == "0" || s == "false" {
                    Some(false)
                } else {
                    None
                }
            });

        Ok(TUICConfig {
            name,
            server,
            port,
            uuid,
            password,
            congestion,
            udp_relay_mode,
            sni,
            alpn,
            disable_sni,
            zero_rtt_handshake,
            allow_insecure,
        })
    }

    pub fn to_singbox(&self) -> serde_json::Value {
        let mut outbound = serde_json::json!({
            "type": "tuic",
            "tag": self.name,
            "server": self.server,
            "server_port": self.port,
            "uuid": self.uuid,
            "password": self.password,
        });

        if let Some(ref congestion) = self.congestion {
            outbound["congestion_control"] = serde_json::json!(congestion);
        }

        if let Some(ref udp_relay_mode) = self.udp_relay_mode {
            outbound["udp_relay_mode"] = serde_json::json!(udp_relay_mode);
        }

        let mut tls_config = serde_json::json!({
            "enabled": true
        });
        if let Some(ref sni) = self.sni {
            tls_config["server_name"] = serde_json::json!(sni);
        }
        if let Some(disable_sni) = self.disable_sni {
            tls_config["disable_sni"] = serde_json::json!(disable_sni);
        }
        if let Some(zero_rtt) = self.zero_rtt_handshake {
            tls_config["zero_rtt_handshake"] = serde_json::json!(zero_rtt);
        }
        if let Some(allow_insecure) = self.allow_insecure {
            tls_config["insecure"] = serde_json::json!(allow_insecure);
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
            serde_yaml::Value::String("tuic".to_string())
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
            serde_yaml::Value::String(self.password.clone())
        );

        if let Some(ref congestion) = self.congestion {
            proxy.insert(
                serde_yaml::Value::String("congestion_control".to_string()),
                serde_yaml::Value::String(congestion.clone())
            );
        }

        if let Some(ref sni) = self.sni {
            proxy.insert(
                serde_yaml::Value::String("sni".to_string()),
                serde_yaml::Value::String(sni.clone())
            );
        }

        if let Some(ref alpn) = self.alpn {
            proxy.insert(
                serde_yaml::Value::String("alpn".to_string()),
                serde_yaml::Value::String(alpn.clone())
            );
        }

        if let Some(disable_sni) = self.disable_sni {
            proxy.insert(
                serde_yaml::Value::String("disable-sni".to_string()),
                serde_yaml::Value::Bool(disable_sni)
            );
        }

        if let Some(zero_rtt) = self.zero_rtt_handshake {
            proxy.insert(
                serde_yaml::Value::String("zero-rtt-handshake".to_string()),
                serde_yaml::Value::Bool(zero_rtt)
            );
        }

        if let Some(ref udp_relay_mode) = self.udp_relay_mode {
            proxy.insert(
                serde_yaml::Value::String("udp-relay-mode".to_string()),
                serde_yaml::Value::String(udp_relay_mode.clone())
            );
        }

        if let Some(allow_insecure) = self.allow_insecure {
            proxy.insert(
                serde_yaml::Value::String("allow-insecure".to_string()),
                serde_yaml::Value::Bool(allow_insecure)
            );
        }

        serde_yaml::Value::Mapping(proxy)
    }
}
