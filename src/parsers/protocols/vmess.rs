//! VMess protocol parser

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use crate::utils::base64_utils;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VMessConfig {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub uuid: String,
    pub security: String,
    pub network: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
}

impl VMessConfig {
    pub fn parse(url: &str) -> Result<Self> {
        if !url.starts_with("vmess://") {
            bail!("Not a valid VMess URL");
        }

        let base64_part = &url[8..];
        let decoded = base64_utils::decode(base64_part)?;
        let json_str = String::from_utf8(decoded)?;
        let vmess_data: serde_json::Value = serde_json::from_str(&json_str)?;

        let uuid = vmess_data["id"].as_str().unwrap_or("").to_string();
        let server = vmess_data["add"].as_str().unwrap_or("").to_string();
        let port = vmess_data["port"].as_str().unwrap_or("0").parse::<u16>().unwrap_or(0);
        let name = vmess_data["ps"].as_str().unwrap_or("VMess").to_string();
        let security = vmess_data["scy"].as_str().unwrap_or("auto").to_string();
        let network = vmess_data["net"].as_str().unwrap_or("tcp").to_string();
        let tls = vmess_data["tls"].as_str().map(|s| s.to_string());
        let sni = vmess_data["sni"].as_str().map(|s| s.to_string());
        
        let path = vmess_data["path"].as_str().map(|s| s.to_string());
        let host = vmess_data["host"].as_str().map(|s| s.to_string());

        Ok(VMessConfig {
            name,
            server,
            port,
            uuid,
            security,
            network,
            path,
            host,
            tls,
            sni,
        })
    }

    pub fn to_singbox(&self) -> serde_json::Value {
        let mut outbound = serde_json::json!({
            "type": "vmess",
            "tag": self.name,
            "server": self.server,
            "server_port": self.port,
            "uuid": self.uuid,
            "security": self.security,
        });

        if self.network == "ws" {
            let mut transport = serde_json::json!({
                "type": "ws",
            });
            if let Some(ref path) = self.path {
                transport["path"] = serde_json::json!(path);
            }
            if let Some(ref host) = self.host {
                transport["headers"] = serde_json::json!({
                    "Host": host
                });
            }
            outbound["transport"] = transport;
        }

        if self.tls.as_deref() == Some("tls") {
            let mut tls_config = serde_json::json!({});
            if let Some(ref sni) = self.sni {
                tls_config["server_name"] = serde_json::json!(sni);
            }
            outbound["tls"] = tls_config;
        }

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
            serde_yaml::Value::String("vmess".to_string())
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
            serde_yaml::Value::String("cipher".to_string()),
            serde_yaml::Value::String(self.security.clone())
        );
        proxy.insert(
            serde_yaml::Value::String("network".to_string()),
            serde_yaml::Value::String(self.network.clone())
        );

        if self.tls.as_deref() == Some("tls") {
            proxy.insert(
                serde_yaml::Value::String("tls".to_string()),
                serde_yaml::Value::Bool(true)
            );
            if let Some(ref sni) = self.sni {
                proxy.insert(
                    serde_yaml::Value::String("servername".to_string()),
                    serde_yaml::Value::String(sni.clone())
                );
            }
        }

        serde_yaml::Value::Mapping(proxy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_vmess() {
        // Example VMess URL (base64 encoded JSON)
        let json = r#"{"v":"2","ps":"Test VMess","add":"example.com","port":"443","id":"uuid-here","scy":"auto","net":"ws","tls":"tls"}"#;
        let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, json);
        let url = format!("vmess://{}", encoded);
        
        let config = VMessConfig::parse(&url).unwrap();
        assert_eq!(config.name, "Test VMess");
        assert_eq!(config.server, "example.com");
        assert_eq!(config.port, 443);
    }
}
