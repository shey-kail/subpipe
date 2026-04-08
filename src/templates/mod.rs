//! Templates module - default configuration templates

pub mod interpolation;

pub use interpolation::InterpolationParser;

/// Generate default Clash configuration template
pub fn generate_clash_template() -> String {
    r#"mixed-port: 7890
allow-lan: true
bind-address: '*'
mode: rule
log-level: info
ipv6: true
external-controller: ':9090'
external-ui: dashboard
secret: '123456'

dns:
  enable: true
  listen: 0.0.0.0:53
  ipv6: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter:
    - '*.lan'
    - '*.linksys.com'
    - '*.linksyssmartwifi.com'
    - 'swscan.apple.com'
    - 'mesu.apple.com'
    - '*.msftconnecttest.com'
    - '*.msftncsi.com'
    - 'time.*.com'
    - 'time.*.gov'
    - 'time.*.edu.cn'
    - 'time.*.apple.com'
    - 'ntp.*.com'
    - '+.pool.ntp.org'
    - 'time1.cloud.tencent.com'
    - '+.music.163.com'
    - '*.126.net'
    - 'musicapi.taihe.com'
    - 'music.taihe.com'
    - 'songsearch.kugou.com'
    - 'trackercdn.kugou.com'
    - '*.kuwo.cn'
    - '+.y.qq.com'
    - '+.music.tc.qq.com'
    - 'aqqmusic.tc.qq.com'
    - '*.xiami.com'
    - '+.music.migu.cn'
    - '+.srv.nintendo.net'
    - '+.stun.playstation.net'
    - 'xbox.*.microsoft.com'
    - '+.xboxlive.com'
    - 'localhost.ptlogin2.qq.com'
    - 'proxy.golang.org'
    - 'stun.*.*'
    - '+.stun.*.*.*.*'
    - 'heartbeat.belkin.com'
    - '*.linksys.com'
    - '*.linksyssmartwifi.com'
    - '*.router.asus.com'
    - 'mesu.apple.com'
    - 'swscan.apple.com'
    - 'swquery.apple.com'
    - 'swdownload.apple.com'
    - 'swcdn.apple.com'
    - 'swdist.apple.com'
    - 'lens.l.google.com'
    - 'stun.l.google.com'
    - '+.nflxvideo.net'
    - '*.square-enix.com'
    - '*.finalfantasyxiv.com'
    - '*.ffxiv.com'
    - '*.mcdn.bilivideo.cn'
  nameserver:
    - 223.5.5.5
    - 114.114.114.114
    - 119.29.29.29
    - 117.50.10.10
  fallback:
    - 8.8.8.8
    - 1.1.1.1
    - tls://dns.rubyfish.cn:853
    - tls://1.0.0.1:853
  fallback-filter:
    geoip: true
    ipcidr:
      - 240.0.0.0/4

proxies: []

proxy-groups:
  - name: '🚀 Select'
    type: select
    url: http://www.gstatic.com/generate_204
    interval: 600
    proxies:
      - '🚀 Manual'
      - '♻️ Auto'
      - '🔯 Fallback'
      - '🔮 LoadBalance'

  - name: '🚀 Manual'
    type: select
    url: http://www.gstatic.com/generate_204
    interval: 600
    proxies:
      - '{{ALL-TAG}}'

  - name: '♻️ Auto'
    type: url-test
    url: http://www.gstatic.com/generate_204
    interval: 600
    tolerance: 150
    proxies:
      - '{{ALL-TAG}}'

  - name: '🔯 Fallback'
    type: fallback
    url: http://www.gstatic.com/generate_204
    interval: 600
    proxies:
      - '{{ALL-TAG}}'

  - name: '🔮 LoadBalance'
    type: load-balance
    url: http://www.gstatic.com/generate_204
    interval: 600
    proxies:
      - '{{ALL-TAG}}'

rule-providers:
  reject:
    type: http
    behavior: domain
    url: 'https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/reject.txt'
    path: ./ruleset/reject.yaml
    interval: 86400
  icloud:
    type: http
    behavior: domain
    url: 'https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/icloud.txt'
    path: ./ruleset/icloud.yaml
    interval: 86400
  apple:
    type: http
    behavior: domain
    url: 'https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/apple.txt'
    path: ./ruleset/apple.yaml
    interval: 86400
  google:
    type: http
    behavior: domain
    url: 'https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/google.txt'
    path: ./ruleset/google.yaml
    interval: 86400
  proxy:
    type: http
    behavior: domain
    url: 'https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/proxy.txt'
    path: ./ruleset/proxy.yaml
    interval: 86400
  direct:
    type: http
    behavior: domain
    url: 'https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/direct.txt'
    path: ./ruleset/direct.yaml
    interval: 86400
  private:
    type: http
    behavior: domain
    url: 'https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/private.txt'
    path: ./ruleset/private.yaml
    interval: 86400
  gfw:
    type: http
    behavior: domain
    url: 'https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/gfw.txt'
    path: ./ruleset/gfw.yaml
    interval: 86400
  telegramcidr:
    type: http
    behavior: ipcidr
    url: 'https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/telegramcidr.txt'
    path: ./ruleset/telegramcidr.yaml
    interval: 86400
  cncidr:
    type: http
    behavior: ipcidr
    url: 'https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/cncidr.txt'
    path: ./ruleset/cncidr.yaml
    interval: 86400
  lancidr:
    type: http
    behavior: ipcidr
    url: 'https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/lancidr.txt'
    path: ./ruleset/lancidr.yaml
    interval: 86400
  applications:
    type: http
    behavior: classical
    url: 'https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/applications.txt'
    path: ./ruleset/applications.yaml
    interval: 86400

rules:
  - RULE-SET,applications,DIRECT
  - RULE-SET,private,DIRECT
  - RULE-SET,reject,REJECT
  - RULE-SET,icloud,DIRECT
  - RULE-SET,apple,DIRECT
  - RULE-SET,google,🚀 Select
  - RULE-SET,proxy,🚀 Select
  - RULE-SET,direct,DIRECT
  - RULE-SET,lancidr,DIRECT,no-resolve
  - RULE-SET,cncidr,DIRECT,no-resolve
  - RULE-SET,telegramcidr,🚀 Select,no-resolve
  - GEOIP,LAN,DIRECT,no-resolve
  - GEOIP,CN,DIRECT,no-resolve
  - MATCH,🚀 Select
"#
    .to_string()
}

/// Generate default Sing-box configuration template
pub fn generate_singbox_template() -> String {
    use serde_json::json;

    // Use a placeholder for node names that will be expanded later
    let template = json!({
        "log": {
            "level": "info",
            "timestamp": true
        },
        "dns": {
            "servers": [
                {
                    "tag": "local",
                    "address": "223.5.5.5",
                    "detour": "DIRECT"
                },
                {
                    "tag": "remote",
                    "address": "8.8.8.8",
                    "detour": "Proxy"
                }
            ],
            "final": "local",
            "strategy": "prefer_ipv4"
        },
        "inbounds": [
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "0.0.0.0",
                "listen_port": 2080
            },
            {
                "type": "tun",
                "tag": "tun-in",
                "address": ["198.18.0.1/16"],
                "mtu": 9000,
                "stack": "system",
                "auto_route": true,
                "strict_route": true,
                "sniff": true
            }
        ],
        "outbounds": [
            {
                "tag": "DIRECT",
                "type": "direct"
            },
            {
                "tag": "REJECT",
                "type": "block"
            },
            {
                "tag": "Proxy",
                "type": "selector",
                "interrupt_exist_connections": true,
                "default": "Auto",
                "outbounds": ["Auto", "Manual"]
            },
            {
                "tag": "Auto",
                "type": "urltest",
                "url": "https://www.gstatic.com/generate_204",
                "interval": "3m",
                "tolerance": 50,
                "outbounds": ["__NODE_NAMES__"]
            },
            {
                "tag": "Manual",
                "type": "selector",
                "interrupt_exist_connections": true,
                "outbounds": ["__NODE_NAMES__"]
            }
        ],
        "route": {
            "rules": [
                {"action": "sniff"},
                {"action": "hijack-dns", "protocol": "dns"},
                {"clash_mode": "global", "action": "route", "outbound": "Proxy"},
                {"clash_mode": "direct", "action": "route", "outbound": "DIRECT"},
                {"rule_set": "ads", "action": "reject"},
                {"rule_set": ["microsoft-cn", "games-cn", "network-test", "applications", "cn", "cn-ip", "private-ip", "private"], "action": "route", "outbound": "DIRECT"},
                {"rule_set": ["proxy", "telegram-ip"], "action": "route", "outbound": "Proxy"}
            ],
            "rule_set": [
                {"tag": "ads", "type": "remote", "format": "binary", "url": "https://cdn.jsdelivr.net/gh/DustinWin/ruleset_geodata@sing-box-ruleset/ads.srs", "download_detour": "Proxy", "update_interval": "1d"},
                {"tag": "private", "type": "remote", "format": "binary", "url": "https://cdn.jsdelivr.net/gh/DustinWin/ruleset_geodata@sing-box-ruleset/private.srs", "download_detour": "Proxy", "update_interval": "1d"},
                {"tag": "microsoft-cn", "type": "remote", "format": "binary", "url": "https://cdn.jsdelivr.net/gh/DustinWin/ruleset_geodata@sing-box-ruleset/microsoft-cn.srs", "download_detour": "Proxy", "update_interval": "1d"},
                {"tag": "apple-cn", "type": "remote", "format": "binary", "url": "https://cdn.jsdelivr.net/gh/DustinWin/ruleset_geodata@sing-box-ruleset/apple-cn.srs", "download_detour": "Proxy", "update_interval": "1d"},
                {"tag": "google-cn", "type": "remote", "format": "binary", "url": "https://cdn.jsdelivr.net/gh/DustinWin/ruleset_geodata@sing-box-ruleset/google-cn.srs", "download_detour": "Proxy", "update_interval": "1d"},
                {"tag": "games-cn", "type": "remote", "format": "binary", "url": "https://cdn.jsdelivr.net/gh/DustinWin/ruleset_geodata@sing-box-ruleset/games-cn.srs", "download_detour": "Proxy", "update_interval": "1d"},
                {"tag": "network-test", "type": "remote", "format": "binary", "url": "https://cdn.jsdelivr.net/gh/DustinWin/ruleset_geodata@sing-box-ruleset/networktest.srs", "download_detour": "Proxy", "update_interval": "1d"},
                {"tag": "applications", "type": "remote", "format": "binary", "url": "https://cdn.jsdelivr.net/gh/DustinWin/ruleset_geodata@sing-box-ruleset/applications.srs", "download_detour": "Proxy", "update_interval": "1d"},
                {"tag": "proxy", "type": "remote", "format": "binary", "url": "https://cdn.jsdelivr.net/gh/DustinWin/ruleset_geodata@sing-box-ruleset/proxy.srs", "download_detour": "Proxy", "update_interval": "1d"},
                {"tag": "cn", "type": "remote", "format": "binary", "url": "https://cdn.jsdelivr.net/gh/DustinWin/ruleset_geodata@sing-box-ruleset/cn.srs", "download_detour": "Proxy", "update_interval": "1d"},
                {"tag": "telegram-ip", "type": "remote", "format": "binary", "url": "https://cdn.jsdelivr.net/gh/DustinWin/ruleset_geodata@sing-box-ruleset/telegramip.srs", "download_detour": "Proxy", "update_interval": "1d"},
                {"tag": "private-ip", "type": "remote", "format": "binary", "url": "https://cdn.jsdelivr.net/gh/DustinWin/ruleset_geodata@sing-box-ruleset/privateip.srs", "download_detour": "Proxy", "update_interval": "1d"},
                {"tag": "cn-ip", "type": "remote", "format": "binary", "url": "https://cdn.jsdelivr.net/gh/DustinWin/ruleset_geodata@sing-box-ruleset/cnip.srs", "download_detour": "Proxy", "update_interval": "1d"}
            ],
            "final": "Proxy",
            "auto_detect_interface": true
        },
        "experimental": {
            "cache_file": {
                "enabled": true,
                "path": "cache.db",
                "store_fakeip": false
            },
            "clash_api": {
                "external_controller": "0.0.0.0:9090",
                "external_ui": "dashboard",
                "external_ui_download_url": "https://github.com/MetaCubeX/Yacd-meta/archive/gh-pages.zip",
                "external_ui_download_detour": "Proxy",
                "default_mode": "rule"
            }
        }
    });

    serde_json::to_string_pretty(&template).unwrap_or_default()
}

/// Generate default Surge configuration template
pub fn generate_surge_template() -> String {
    r#"[General]
loglevel = notify
dns-server = 223.5.5.5, 114.114.114.114
allow-wifi-access = false
skip-proxy = 127.0.0.1, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, localhost, *.local
ipv6 = false
test-timeout = 5
proxy-test-url = http://www.gstatic.com/generate_204

[Proxy]

[Proxy Group]
🚀 Select = select, {{ALL-TAG}}
🇭🇰 香港 = select, {{INCLUDE-TAG:香港}}
🇯🇵 日本 = select, {{INCLUDE-TAG:日本}}
🇹🇼 台湾 = select, {{INCLUDE-TAG:台湾}}
🇸🇬 新加坡 = select, {{INCLUDE-TAG:新加坡}}
🌐 全球 = select, {{EXCLUDE-TAG:香港,台湾}}

[Rule]
GEOIP,CN,DIRECT
MATCH,🚀 Select
"#.to_string()
}
