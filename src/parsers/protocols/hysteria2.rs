//! Hysteria2 protocol parser

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hysteria2Config {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub password: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub obfs: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub obfs_password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub insecure: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alpn: Option<String>,
}

impl Hysteria2Config {
    pub fn parse(url: &str) -> Result<Self> {
        if !url.starts_with("hysteria2://") && !url.starts_with("hy2://") && !url.starts_with("hysteria://") {
            bail!("Not a valid Hysteria2 URL");
        }

        // Determine scheme length
        let scheme_len = if url.starts_with("hysteria2://") {
            12
        } else if url.starts_with("hysteria://") {
            11
        } else {
            6 // hy2://
        };
        let without_scheme = &url[scheme_len..];
        
        // Parse hysteria2://password@server:port?params#name
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
            bail!("Invalid Hysteria2 URL format");
        }

        let password = urlencoding::decode(password_host_port[0])
            .unwrap_or_else(|_| password_host_port[0].to_string().into())
            .to_string();

        // Extract host:port from the string (before any path/query)
        // The format is host:port/path?query - we only want host:port
        let host_port_str = password_host_port[1].splitn(2, '/').next().unwrap_or(password_host_port[1]);
        let host_port: Vec<&str> = host_port_str.rsplitn(2, ':').collect();
        if host_port.len() != 2 {
            bail!("Invalid host:port format");
        }

        let server = host_port[1].to_string();
        // Parse port, stripping any non-numeric trailing characters
        let port_str = host_port[0].trim_end_matches(|c: char| !c.is_ascii_digit());
        let port = port_str.parse::<u16>()?;

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
            .map(|f| urlencoding::decode(f).unwrap_or_else(|_| f.to_string().into()).to_string())
            .unwrap_or("Hysteria2".to_string());
        let obfs = params.get("obfs").map(|s| s.as_str()).map(|s| urlencoding::decode(s).unwrap_or_else(|_| s.to_string().into()).to_string());
        let obfs_password = params.get("obfs-password").map(|s| s.as_str()).map(|s| urlencoding::decode(s).unwrap_or_else(|_| s.to_string().into()).to_string());
        let sni = params.get("sni").map(|s| s.as_str()).map(|s| urlencoding::decode(s).unwrap_or_else(|_| s.to_string().into()).to_string());
        let insecure = params.get("insecure").and_then(|s| {
            if s == "1" || s == "true" {
                Some(true)
            } else if s == "0" || s == "false" {
                Some(false)
            } else {
                None
            }
        });
        let alpn = params.get("alpn").map(|s| s.as_str()).map(|s| urlencoding::decode(s).unwrap_or_else(|_| s.to_string().into()).to_string());

        Ok(Hysteria2Config {
            name,
            server,
            port,
            password,
            obfs,
            obfs_password,
            sni,
            insecure,
            alpn,
        })
    }

    pub fn to_singbox(&self) -> serde_json::Value {
        let mut outbound = serde_json::json!({
            "type": "hysteria2",
            "tag": self.name,
            "server": self.server,
            "server_port": self.port,
            "password": self.password,
        });

        if self.obfs.is_some() || self.obfs_password.is_some() {
            let mut obfs_config = serde_json::json!({
                "type": self.obfs.as_deref().unwrap_or("salamander"),
            });
            if let Some(ref obfs_password) = self.obfs_password {
                obfs_config["password"] = serde_json::json!(obfs_password);
            }
            outbound["obfs"] = obfs_config;
        }

        if self.sni.is_some() || self.insecure.is_some() || self.alpn.is_some() {
            let mut tls_config = serde_json::json!({
                "enabled": true
            });
            if let Some(ref sni) = self.sni {
                tls_config["server_name"] = serde_json::json!(sni);
            }
            if let Some(insecure) = self.insecure {
                tls_config["insecure"] = serde_json::json!(insecure);
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
            serde_yaml::Value::String("hysteria2".to_string())
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

        if let Some(insecure) = self.insecure {
            proxy.insert(
                serde_yaml::Value::String("skip-cert-verify".to_string()),
                serde_yaml::Value::Bool(insecure)
            );
        }

        serde_yaml::Value::Mapping(proxy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hysteria2_hy2() {
        let url = "hy2://pass@host:1234#MyHY2";
        let config = Hysteria2Config::parse(url).unwrap();
        assert_eq!(config.name, "MyHY2");
        assert_eq!(config.password, "pass");
        assert_eq!(config.server, "host");
        assert_eq!(config.port, 1234);
    }

    #[test]
    fn test_parse_hysteria2_hysteria() {
        let url = "hysteria://pass@host:1234#MyHysteria";
        let config = Hysteria2Config::parse(url).unwrap();
        assert_eq!(config.name, "MyHysteria");
        assert_eq!(config.password, "pass");
        assert_eq!(config.server, "host");
        assert_eq!(config.port, 1234);
    }

    #[test]
    fn test_to_singbox_with_tls_enabled() {
        // Test that hysteria2 with sni has tls.enabled = true
        let url = "hy2://pass@host:1234?sni=example.com#MyHY2";
        let config = Hysteria2Config::parse(url).unwrap();
        let singbox = config.to_singbox();

        let tls = singbox.get("tls").unwrap();
        assert!(tls.get("enabled").unwrap().as_bool().unwrap(), "TLS enabled should be true");
        assert_eq!(tls.get("server_name").unwrap().as_str().unwrap(), "example.com");
    }

    #[test]
    fn test_to_singbox_without_tls() {
        // Test that hysteria2 without sni/insecure has no tls config
        let url = "hy2://pass@host:1234#MyHY2";
        let config = Hysteria2Config::parse(url).unwrap();
        let singbox = config.to_singbox();

        assert!(singbox.get("tls").is_none(), "TLS should not be present when not configured");
    }

    #[test]
    fn test_to_singbox_with_insecure() {
        // Test that hysteria2 with insecure has tls.enabled = true
        // Note: bool::parse only accepts "true"/"false", not "1"/"0"
        let url = "hy2://pass@host:1234?insecure=true#MyHY2";
        let config = Hysteria2Config::parse(url).unwrap();
        let singbox = config.to_singbox();

        let tls = singbox.get("tls").unwrap();
        assert!(tls.get("enabled").unwrap().as_bool().unwrap(), "TLS enabled should be true");
        assert!(tls.get("insecure").unwrap().as_bool().unwrap());
    }
}
