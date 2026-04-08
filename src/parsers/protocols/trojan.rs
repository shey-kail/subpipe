//! Trojan protocol parser

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrojanConfig {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub password: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alpn: Option<String>,
}

impl TrojanConfig {
    pub fn parse(url: &str) -> Result<Self> {
        if !url.starts_with("trojan://") {
            bail!("Not a valid Trojan URL");
        }

        // Parse trojan://password@server:port?params#name
        let without_scheme = &url[9..];
        let (main_part, fragment) = if without_scheme.contains('#') {
            let parts: Vec<&str> = without_scheme.splitn(2, '#').collect();
            (parts[0], Some(parts[1]))
        } else {
            (without_scheme, None)
        };

        let (password_server_port, query_part) = if main_part.contains('?') {
            let parts: Vec<&str> = main_part.splitn(2, '?').collect();
            (parts[0], Some(parts[1]))
        } else {
            (main_part, None)
        };

        let password_host_port: Vec<&str> = password_server_port.splitn(2, '@').collect();
        if password_host_port.len() != 2 {
            bail!("Invalid Trojan URL format");
        }

        let password = urlencoding::decode(password_host_port[0])
            .unwrap_or_else(|_| password_host_port[0].to_string().into())
            .to_string();
        
        let host_port: Vec<&str> = password_host_port[1].rsplitn(2, ':').collect();
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
            .unwrap_or_else(|| "Trojan".to_string());
        let network = params.get("type").map(|s| s.as_str()).map(|s| s.to_string());
        let path = params.get("path").map(|s| s.as_str()).map(|s| s.to_string());
        let host = params.get("host").map(|s| s.as_str()).map(|s| s.to_string());
        let sni = params.get("sni").map(|s| s.as_str()).map(|s| s.to_string());
        let alpn = params.get("alpn").map(|s| s.as_str()).map(|s| s.to_string());

        Ok(TrojanConfig {
            name,
            server,
            port,
            password,
            network,
            path,
            host,
            sni,
            alpn,
        })
    }

    pub fn to_singbox(&self) -> serde_json::Value {
        let mut outbound = serde_json::json!({
            "type": "trojan",
            "tag": self.name,
            "server": self.server,
            "server_port": self.port,
            "password": self.password,
        });

        if let Some(ref network) = self.network {
            if network == "ws" {
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
            } else if network == "grpc" {
                let mut transport = serde_json::json!({
                    "type": "grpc",
                });
                if let Some(ref path) = self.path {
                    transport["service_name"] = serde_json::json!(path);
                }
                outbound["transport"] = transport;
            }
        }

        if self.sni.is_some() || self.alpn.is_some() {
            let mut tls_config = serde_json::json!({
                "enabled": true,
                "insecure": true
            });
            if let Some(ref sni) = self.sni {
                tls_config["server_name"] = serde_json::json!(sni);
            }
            if let Some(ref alpn) = self.alpn {
                tls_config["alpn"] = serde_json::json!([alpn]);
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
            serde_yaml::Value::String("trojan".to_string())
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
            serde_yaml::Value::String("password".to_string()),
            serde_yaml::Value::String(self.password.clone())
        );

        if let Some(ref sni) = self.sni {
            proxy.insert(
                serde_yaml::Value::String("sni".to_string()),
                serde_yaml::Value::String(sni.clone())
            );
        }

        serde_yaml::Value::Mapping(proxy)
    }
}
