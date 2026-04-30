//! Proxy parser - parses different proxy protocol URLs

use anyhow::{Result, bail};
use crate::parsers::protocols::*;

/// Parsed proxy configuration
#[derive(Debug, Clone)]
pub enum ProxyConfig {
    ShadowSocks(ShadowSocksConfig),
    VMess(VMessConfig),
    VLESS(VLESSConfig),
    Hysteria2(Hysteria2Config),
    Trojan(TrojanConfig),
    TUIC(TUICConfig),
    AnyTLS(AnyTLSConfig),
}

impl ProxyConfig {
    pub fn name(&self) -> &str {
        match self {
            ProxyConfig::ShadowSocks(c) => &c.name,
            ProxyConfig::VMess(c) => &c.name,
            ProxyConfig::VLESS(c) => &c.name,
            ProxyConfig::Hysteria2(c) => &c.name,
            ProxyConfig::Trojan(c) => &c.name,
            ProxyConfig::TUIC(c) => &c.name,
            ProxyConfig::AnyTLS(c) => &c.name,
        }
    }

    // 暂时未使用的方法
    // pub fn server(&self) -> &str {
    //     match self {
    //         ProxyConfig::ShadowSocks(c) => &c.server,
    //         ProxyConfig::VMess(c) => &c.server,
    //         ProxyConfig::VLESS(c) => &c.server,
    //         ProxyConfig::Hysteria2(c) => &c.server,
    //         ProxyConfig::Trojan(c) => &c.server,
    //         ProxyConfig::TUIC(c) => &c.server,
    //     }
    // }

    // 暂时未使用的方法
    // pub fn port(&self) -> u16 {
    //     match self {
    //         ProxyConfig::ShadowSocks(c) => c.port,
    //         ProxyConfig::VMess(c) => c.port,
    //         ProxyConfig::VLESS(c) => c.port,
    //         ProxyConfig::Hysteria2(c) => c.port,
    //         ProxyConfig::Trojan(c) => c.port,
    //         ProxyConfig::TUIC(c) => c.port,
    //     }
    // }

    pub fn to_singbox(&self) -> serde_json::Value {
        match self {
            ProxyConfig::ShadowSocks(c) => c.to_singbox(),
            ProxyConfig::VMess(c) => c.to_singbox(),
            ProxyConfig::VLESS(c) => c.to_singbox(),
            ProxyConfig::Hysteria2(c) => c.to_singbox(),
            ProxyConfig::Trojan(c) => c.to_singbox(),
            ProxyConfig::TUIC(c) => c.to_singbox(),
            ProxyConfig::AnyTLS(c) => c.to_singbox(),
        }
    }

    pub fn to_clash(&self) -> serde_yaml::Value {
        match self {
            ProxyConfig::ShadowSocks(c) => c.to_clash(),
            ProxyConfig::VMess(c) => c.to_clash(),
            ProxyConfig::VLESS(c) => c.to_clash(),
            ProxyConfig::Hysteria2(c) => c.to_clash(),
            ProxyConfig::Trojan(c) => c.to_clash(),
            ProxyConfig::TUIC(c) => c.to_clash(),
            ProxyConfig::AnyTLS(c) => c.to_clash(),
        }
    }
}

/// Proxy type enum
/// 暂时未使用，保留以备将来需要类型判断时使用
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyType {
    ShadowSocks,
    VMess,
    VLESS,
    Hysteria2,
    Trojan,
    TUIC,
}

/// Proxy parser
pub struct ProxyParser;

impl ProxyParser {
    /// Parse a proxy URL into a ProxyConfig
    pub fn parse(url: &str) -> Result<ProxyConfig> {
        if url.starts_with("ss://") {
            Ok(ProxyConfig::ShadowSocks(ShadowSocksConfig::parse(url)?))
        } else if url.starts_with("vmess://") {
            Ok(ProxyConfig::VMess(VMessConfig::parse(url)?))
        } else if url.starts_with("vless://") {
            Ok(ProxyConfig::VLESS(VLESSConfig::parse(url)?))
        } else if url.starts_with("hysteria2://") || url.starts_with("hy2://") || url.starts_with("hysteria://") {
            Ok(ProxyConfig::Hysteria2(Hysteria2Config::parse(url)?))
        } else if url.starts_with("trojan://") {
            Ok(ProxyConfig::Trojan(TrojanConfig::parse(url)?))
        } else if url.starts_with("tuic://") {
            Ok(ProxyConfig::TUIC(TUICConfig::parse(url)?))
        } else if url.starts_with("anytls://") {
            Ok(ProxyConfig::AnyTLS(AnyTLSConfig::parse(url)?))
        } else {
            bail!("Unknown proxy protocol: {}", url.split("://").next().unwrap_or("unknown"))
        }
    }

    // 暂时未使用的函数
    // /// Get the proxy type from URL
    // pub fn get_type(url: &str) -> Option<ProxyType> {
    //     if url.starts_with("ss://") {
    //         Some(ProxyType::ShadowSocks)
    //     } else if url.starts_with("vmess://") {
    //         Some(ProxyType::VMess)
    //     } else if url.starts_with("vless://") {
    //         Some(ProxyType::VLESS)
    //     } else if url.starts_with("hysteria2://") || url.starts_with("hy2://") || url.starts_with("hysteria://") {
    //         Some(ProxyType::Hysteria2)
    //     } else if url.starts_with("trojan://") {
    //         Some(ProxyType::Trojan)
    //     } else if url.starts_with("tuic://") {
    //         Some(ProxyType::TUIC)
    //     } else {
    //         None
    //     }
    // }
}
