//! VLESS protocol parser

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use urlencoding;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VLESSConfig {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub uuid: String,
    pub flow: String,
    pub security: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encryption: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alpn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pbk: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub packet_encoding: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub insecure: Option<bool>,
}

impl VLESSConfig {
    pub fn parse(url: &str) -> Result<Self> {
        if !url.starts_with("vless://") {
            bail!("Not a valid VLESS URL");
        }

        // Parse vless://uuid@server:port?params#name
        let without_scheme = &url[8..];
        let (main_part, fragment) = if without_scheme.contains('#') {
            let parts: Vec<&str> = without_scheme.splitn(2, '#').collect();
            let decoded_name = urlencoding::decode(parts[1])
                .unwrap_or_else(|_| parts[1].to_string().into())
                .to_string();
            (parts[0], Some(decoded_name))
        } else {
            (without_scheme, None)
        };

        let (uuid_server_port, query_part) = if main_part.contains('?') {
            let parts: Vec<&str> = main_part.splitn(2, '?').collect();
            (parts[0], Some(parts[1]))
        } else {
            (main_part, None)
        };

        let uuid_host_port: Vec<&str> = uuid_server_port.splitn(2, '@').collect();
        if uuid_host_port.len() != 2 {
            bail!("Invalid VLESS URL format");
        }

        let uuid = uuid_host_port[0].to_string();
        let host_port_str = uuid_host_port[1];
        
        let (server, port) = if host_port_str.starts_with('[') {
            // IPv6
            let end_bracket = host_port_str.find(']').ok_or_else(|| anyhow::anyhow!("Invalid IPv6 address"))?;
            let server = &host_port_str[1..end_bracket];
            let rest = &host_port_str[end_bracket+1..];
            if rest.starts_with(':') {
                let port = rest[1..].parse::<u16>()?;
                (server.to_string(), port)
            } else {
                (server.to_string(), 443) // Default port
            }
        } else {
            let host_port: Vec<&str> = host_port_str.rsplitn(2, ':').collect();
            if host_port.len() == 2 {
                (host_port[1].to_string(), host_port[0].parse::<u16>()?)
            } else {
                (host_port_str.to_string(), 443) // Default port
            }
        };

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
            .unwrap_or_else(|| "VLESS".to_string());
        let flow = params.get("flow").cloned().unwrap_or_default();
        let security = params.get("security").cloned().unwrap_or_default();
        let encryption = params.get("encryption").cloned();
        let network = params.get("type").cloned();
        let path = params.get("path").cloned();
        let host = params.get("host").cloned();
        let sni = params.get("sni").cloned();
        let fp = params.get("fp").cloned();
        let alpn = params.get("alpn").cloned();
        let pbk = params.get("pbk").cloned();
        let sid = params.get("sid").cloned();
        let packet_encoding = params.get("packetEncoding").cloned();
        let insecure = params.get("insecure").and_then(|s| {
            if s == "1" || s == "true" {
                Some(true)
            } else if s == "0" || s == "false" {
                Some(false)
            } else {
                None
            }
        });

        Ok(VLESSConfig {
            name,
            server,
            port,
            uuid,
            flow,
            security,
            encryption,
            network,
            path,
            host,
            sni,
            fp,
            alpn,
            pbk,
            sid,
            packet_encoding,
            insecure,
        })
    }

    pub fn to_singbox(&self) -> serde_json::Value {
        let mut outbound = serde_json::json!({
            "type": "vless",
            "tag": self.name,
            "server": self.server,
            "server_port": self.port,
            "uuid": self.uuid,
        });

        if !self.flow.is_empty() {
            outbound["flow"] = serde_json::json!(self.flow);
        }

        if !self.security.is_empty() {
            if self.security == "tls" || self.security == "reality" {
                let mut tls_config = serde_json::json!({
                    "enabled": true,
                    "insecure": self.insecure.unwrap_or(false),
                });

                if let Some(ref sni) = self.sni {
                    tls_config["server_name"] = serde_json::json!(sni);
                } else if let Some(ref host) = self.host {
                    tls_config["server_name"] = serde_json::json!(host);
                }

                if let Some(ref fp) = self.fp {
                    tls_config["utls"] = serde_json::json!({
                        "enabled": true,
                        "fingerprint": fp
                    });
                } else {
                     tls_config["utls"] = serde_json::json!({
                        "enabled": true,
                        "fingerprint": "chrome"
                    });
                }

                if self.security == "reality" {
                    let mut reality_config = serde_json::json!({
                        "enabled": true,
                    });
                    if let Some(ref pbk) = self.pbk {
                        reality_config["public_key"] = serde_json::json!(pbk);
                    }
                    if let Some(ref sid) = self.sid {
                        reality_config["short_id"] = serde_json::json!(sid);
                    }
                    tls_config["reality"] = reality_config;
                }

                if let Some(ref alpn) = self.alpn {
                    tls_config["alpn"] = serde_json::json!(alpn.split(',').collect::<Vec<&str>>());
                }

                outbound["tls"] = tls_config;
            }
        }

        // Add packet_encoding for xudp (used with xtls-rprx-vision flow)
        if let Some(ref packet_encoding) = self.packet_encoding {
            outbound["packet_encoding"] = serde_json::json!(packet_encoding);
        } else if self.flow == "xtls-rprx-vision" {
            outbound["packet_encoding"] = serde_json::json!("xudp");
        }

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
            serde_yaml::Value::String("vless".to_string())
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

        if !self.flow.is_empty() {
            proxy.insert(
                serde_yaml::Value::String("flow".to_string()),
                serde_yaml::Value::String(self.flow.clone())
            );
        }

        if !self.security.is_empty() {
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
            if let Some(ref fp) = self.fp {
                proxy.insert(
                    serde_yaml::Value::String("client-fingerprint".to_string()),
                    serde_yaml::Value::String(fp.clone())
                );
            }
            if let Some(ref alpn) = self.alpn {
                proxy.insert(
                    serde_yaml::Value::String("alpn".to_string()),
                    serde_yaml::Value::String(alpn.clone())
                );
            }
            if self.security == "reality" {
                if let Some(ref pbk) = self.pbk {
                    proxy.insert(
                        serde_yaml::Value::String("reality-pbk".to_string()),
                        serde_yaml::Value::String(pbk.clone())
                    );
                }
                if let Some(ref sid) = self.sid {
                    proxy.insert(
                        serde_yaml::Value::String("reality-short-id".to_string()),
                        serde_yaml::Value::String(sid.clone())
                    );
                }
            }
        }

        if let Some(ref network) = self.network {
            proxy.insert(
                serde_yaml::Value::String("network".to_string()),
                serde_yaml::Value::String(network.clone())
            );

            if network == "ws" {
                if let Some(ref path) = self.path {
                    proxy.insert(
                        serde_yaml::Value::String("ws-path".to_string()),
                        serde_yaml::Value::String(path.clone())
                    );
                }
                if let Some(ref host) = self.host {
                    proxy.insert(
                        serde_yaml::Value::String("ws-headers".to_string()),
                        serde_yaml::Value::String(format!("Host:{}", host))
                    );
                }
            } else if network == "grpc" {
                if let Some(ref path) = self.path {
                    proxy.insert(
                        serde_yaml::Value::String("grpc-service-name".to_string()),
                        serde_yaml::Value::String(path.clone())
                    );
                }
            }
        }

        serde_yaml::Value::Mapping(proxy)
    }
}
