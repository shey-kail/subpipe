//! ShadowSocks protocol parser

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use crate::utils::base64_utils;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowSocksConfig {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub password: String,
    pub method: String,
}

impl ShadowSocksConfig {
    pub fn parse(url: &str) -> Result<Self> {
        if !url.starts_with("ss://") {
            bail!("Not a valid ShadowSocks URL");
        }

        // Extract name from fragment if present
        let (main_part, name) = if url.contains('#') {
            let parts: Vec<&str> = url.splitn(2, '#').collect();
            let name = urlencoding::decode(parts[1])
                .unwrap_or_else(|_| parts[1].to_string().into())
                .to_string();
            (parts[0][5..].to_string(), name)
        } else {
            (url[5..].to_string(), "ShadowSocks".to_string())
        };

        // Extract query parameters (for plugin support)
        let (main_part_no_query, _query_part) = if main_part.contains('?') {
            let parts: Vec<&str> = main_part.splitn(2, '?').collect();
            (parts[0], Some(parts[1]))
        } else {
            (main_part.as_str(), None)
        };

        let (method, password, server, port) = if main_part_no_query.contains('@') {
            // SIP002: ss://BASE64(method:password)@host:port
            let parts: Vec<&str> = main_part_no_query.splitn(2, '@').collect();
            let decoded_userinfo = base64_utils::decode(parts[0])
                .map(|bytes| String::from_utf8_lossy(&bytes).to_string())
                .unwrap_or_else(|_| parts[0].to_string());
            
            let userinfo_parts: Vec<&str> = decoded_userinfo.splitn(2, ':').collect();
            if userinfo_parts.len() != 2 {
                bail!("Invalid method:password format in SIP002");
            }

            let host_port: Vec<&str> = parts[1].rsplitn(2, ':').collect();
            if host_port.len() != 2 {
                bail!("Invalid host:port format in SIP002");
            }

            (
                userinfo_parts[0].to_string(),
                userinfo_parts[1].to_string(),
                host_port[1].to_string(),
                host_port[0].parse::<u16>()?,
            )
        } else {
            // Legacy: ss://BASE64(method:password@host:port)
            let decoded = base64_utils::decode(main_part_no_query)
                .map(|bytes| String::from_utf8_lossy(&bytes).to_string())?;
            
            let parts: Vec<&str> = decoded.splitn(2, '@').collect();
            if parts.len() != 2 {
                bail!("Invalid ShadowSocks legacy URL format");
            }

            let userinfo_parts: Vec<&str> = parts[0].splitn(2, ':').collect();
            if userinfo_parts.len() != 2 {
                bail!("Invalid method:password format in legacy");
            }

            let host_port: Vec<&str> = parts[1].rsplitn(2, ':').collect();
            if host_port.len() != 2 {
                bail!("Invalid host:port format in legacy");
            }

            (
                userinfo_parts[0].to_string(),
                userinfo_parts[1].to_string(),
                host_port[1].to_string(),
                host_port[0].parse::<u16>()?,
            )
        };

        Ok(ShadowSocksConfig {
            name,
            server,
            port,
            password,
            method,
        })
    }

    pub fn to_singbox(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "shadowsocks",
            "tag": self.name,
            "server": self.server,
            "server_port": self.port,
            "method": self.method,
            "password": self.password,
        })
    }

    pub fn to_clash(&self) -> serde_yaml::Value {
        let mut proxy = serde_yaml::Mapping::new();
        proxy.insert(
            serde_yaml::Value::String("name".to_string()),
            serde_yaml::Value::String(self.name.clone())
        );
        proxy.insert(
            serde_yaml::Value::String("type".to_string()),
            serde_yaml::Value::String("ss".to_string())
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
            serde_yaml::Value::String("cipher".to_string()),
            serde_yaml::Value::String(self.method.clone())
        );
        proxy.insert(
            serde_yaml::Value::String("password".to_string()),
            serde_yaml::Value::String(self.password.clone())
        );

        serde_yaml::Value::Mapping(proxy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_shadowsocks_sip002() {
        // ss://BASE64(method:password)@host:port#name
        let userinfo = "chacha20-ietf-poly1305:6b67b67b67b67b67b67b67";
        let encoded_userinfo = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, userinfo);
        let url = format!("ss://{}@1.2.3.4:1234#MyNode", encoded_userinfo);
        let config = ShadowSocksConfig::parse(&url).unwrap();
        assert_eq!(config.name, "MyNode");
        assert_eq!(config.method, "chacha20-ietf-poly1305");
        assert_eq!(config.password, "6b67b67b67b67b67b67b67");
        assert_eq!(config.server, "1.2.3.4");
        assert_eq!(config.port, 1234);
    }

    #[test]
    fn test_parse_shadowsocks_legacy() {
        // ss://BASE64(method:password@host:port)#name
        let decoded = "chacha20-ietf-poly1305:pass@5.6.7.8:443";
        let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, decoded);
        let url = format!("ss://{}#LegacyNode", encoded);
        let config = ShadowSocksConfig::parse(&url).unwrap();
        assert_eq!(config.name, "LegacyNode");
        assert_eq!(config.method, "chacha20-ietf-poly1305");
        assert_eq!(config.password, "pass");
        assert_eq!(config.server, "5.6.7.8");
        assert_eq!(config.port, 443);
    }
}
