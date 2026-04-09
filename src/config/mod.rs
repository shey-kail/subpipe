//! Configuration module - predefined rule sets and default configs

/// Predefined rule sets
pub mod rules {

    /// Unified rule structure
    pub struct Rule {
        pub name: &'static str,
        pub site_rules: &'static [&'static str],
        pub ip_rules: &'static [&'static str],
    }

    pub const UNIFIED_RULES: &[Rule] = &[
        Rule {
            name: "Ad Block",
            site_rules: &["category-ads-all"],
            ip_rules: &[],
        },
        Rule {
            name: "AI Services",
            site_rules: &["category-ai-!cn"],
            ip_rules: &[],
        },
        Rule {
            name: "Bilibili",
            site_rules: &["bilibili"],
            ip_rules: &[],
        },
        Rule {
            name: "Youtube",
            site_rules: &["youtube"],
            ip_rules: &[],
        },
        Rule {
            name: "Google",
            site_rules: &["google"],
            ip_rules: &["google"],
        },
        Rule {
            name: "Private",
            site_rules: &[],
            ip_rules: &["private"],
        },
        Rule {
            name: "Location:CN",
            site_rules: &["geolocation-cn", "cn"],
            ip_rules: &["cn"],
        },
        Rule {
            name: "Telegram",
            site_rules: &[],
            ip_rules: &["telegram"],
        },
        Rule {
            name: "Github",
            site_rules: &["github", "gitlab"],
            ip_rules: &[],
        },
        Rule {
            name: "Microsoft",
            site_rules: &["microsoft"],
            ip_rules: &[],
        },
        Rule {
            name: "Apple",
            site_rules: &["apple"],
            ip_rules: &[],
        },
        Rule {
            name: "Social Media",
            site_rules: &["facebook", "instagram", "twitter", "tiktok", "linkedin"],
            ip_rules: &[],
        },
        Rule {
            name: "Streaming",
            site_rules: &["netflix", "hulu", "disney", "hbo", "amazon", "bahamut"],
            ip_rules: &[],
        },
        Rule {
            name: "Gaming",
            site_rules: &["steam", "epicgames", "ea", "ubisoft", "blizzard"],
            ip_rules: &[],
        },
        Rule {
            name: "Education",
            site_rules: &["coursera", "edx", "udemy", "khanacademy", "category-scholar-!cn"],
            ip_rules: &[],
        },
        Rule {
            name: "Financial",
            site_rules: &["paypal", "visa", "mastercard", "stripe", "wise"],
            ip_rules: &[],
        },
        Rule {
            name: "Cloud Services",
            site_rules: &["aws", "azure", "digitalocean", "heroku", "dropbox"],
            ip_rules: &[],
        },
        Rule {
            name: "Non-China",
            site_rules: &["geolocation-!cn"],
            ip_rules: &[],
        },
    ];

    /// Rule names that should default to DIRECT instead of Node Select
    pub const DIRECT_DEFAULT_RULES: &[&str] = &["Private", "Location:CN"];

    pub fn get_rule_by_name(name: &str) -> Option<&'static Rule> {
        UNIFIED_RULES.iter().find(|rule| rule.name == name)
    }
}

/// SingBox default configurations
pub mod singbox_config {
    use serde_json::json;

    pub fn default_v1_12() -> serde_json::Value {
        json!({
            "log": {
                "level": "info",
                "timestamp": true
            },
            "dns": {
                "servers": [
                    {
                        "type": "tcp",
                        "tag": "dns_proxy",
                        "server": "1.1.1.1",
                        "domain_resolver": "dns_resolver"
                    },
                    {
                        "type": "https",
                        "tag": "dns_direct",
                        "server": "dns.alidns.com",
                        "domain_resolver": "dns_resolver"
                    },
                    {
                        "type": "udp",
                        "tag": "dns_resolver",
                        "server": "223.5.5.5"
                    },
                    {
                        "type": "fakeip",
                        "tag": "dns_fakeip",
                        "inet4_range": "198.18.0.0/15",
                        "inet6_range": "fc00::/18"
                    }
                ],
                "rules": [
                    {
                        "rule_set": "geolocation-!cn",
                        "query_type": ["A", "AAAA"],
                        "server": "dns_fakeip"
                    },
                    {
                        "rule_set": "geolocation-!cn",
                        "query_type": "CNAME",
                        "server": "dns_proxy"
                    },
                    {
                        "query_type": ["A", "AAAA", "CNAME"],
                        "invert": true,
                        "action": "predefined",
                        "rcode": "REFUSED"
                    }
                ],
                "final": "dns_direct",
                "independent_cache": true
            },
            "ntp": {
                "enabled": true,
                "server": "time.apple.com",
                "server_port": 123,
                "interval": "30m"
            },
            "inbounds": [
                { "type": "mixed", "tag": "mixed-in", "listen": "0.0.0.0", "listen_port": 2080 }
            ],
            "outbounds": [
                { "type": "block", "tag": "REJECT" },
                { "type": "direct", "tag": "DIRECT" }
            ],
            "route": {
                "default_domain_resolver": "dns_resolver",
                "rule_set": [
                    {
                        "tag": "geosite-geolocation-!cn",
                        "type": "local",
                        "format": "binary",
                        "path": "geosite-geolocation-!cn.srs"
                    }
                ],
                "rules": []
            },
            "experimental": {
                "cache_file": {
                    "enabled": true,
                    "store_fakeip": true
                }
            }
        })
    }

    pub fn default_v1_11() -> serde_json::Value {
        json!({
            "log": {
                "level": "info",
                "timestamp": true
            },
            "dns": {
                "servers": [
                    {
                        "tag": "dns_proxy",
                        "address": "tls://1.1.1.1"
                    },
                    {
                        "tag": "dns_direct",
                        "address": "https://dns.alidns.com/dns-query",
                        "detour": "DIRECT",
                        "address_resolver": "dns_resolver"
                    },
                    {
                        "tag": "dns_resolver",
                        "address": "223.5.5.5",
                        "detour": "DIRECT"
                    },
                    {
                        "tag": "dns_fakeip",
                        "address": "fakeip"
                    }
                ],
                "rules": [
                    {
                        "rule_set": "geolocation-!cn",
                        "query_type": ["A", "AAAA"],
                        "server": "dns_fakeip"
                    },
                    {
                        "rule_set": "geolocation-!cn",
                        "query_type": "CNAME",
                        "server": "dns_proxy"
                    },
                    {
                        "query_type": ["A", "AAAA", "CNAME"],
                        "invert": true,
                        "server": "dns_direct",
                        "disable_cache": true
                    }
                ],
                "final": "dns_direct",
                "strategy": "prefer_ipv4",
                "independent_cache": true,
                "fakeip": {
                    "enabled": true,
                    "inet4_range": "198.18.0.0/15",
                    "inet6_range": "fc00::/18"
                }
            },
            "ntp": {
                "enabled": true,
                "server": "time.apple.com",
                "server_port": 123,
                "interval": "30m"
            },
            "inbounds": [
                { "type": "mixed", "tag": "mixed-in", "listen": "0.0.0.0", "listen_port": 2080 }
            ],
            "outbounds": [
                { "type": "block", "tag": "REJECT" },
                { "type": "direct", "tag": "DIRECT" }
            ],
            "route": {
                "rule_set": [],
                "rules": []
            },
            "experimental": {
                "cache_file": {
                    "enabled": true,
                    "store_fakeip": true
                }
            }
        })
    }
}
