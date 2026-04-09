# Subpipe

> A lightweight subscription converter, rewritten in Rust.

## Philosophy

This project is born to **prevent subscription leakage**. By converting subscription content locally, your subscription link never leaves your machine — unlike browser-based converters that send your subscription to third-party servers.

Following the **Unix philosophy**: do one thing and do it well. Subpipe only converts subscription content to various proxy client formats, nothing more.

## Features

- 🚀 High performance, low memory footprint
- 📦 Single binary deployment
- 🎯 Cross-platform (mipsel/aarch64/x86_64)
- 🔄 Support for multiple output formats

## Supported Protocols

ShadowSocks · VMess · VLESS · Hysteria2 · Trojan · TUIC

## Supported Output Formats

Sing-Box · Clash · Surge

## Installation

### Build from Source

```bash
cargo build --release
```

### Pre-built Binaries

Download from GitHub Releases.

## Usage

### Basic Commands

```bash
# Convert subscription to Clash format
curl -sL "https://example.com/sub" | subpipe convert -f clash -o output.yaml

# Convert to Singbox format
curl -sL "https://example.com/sub" | subpipe convert -f singbox -o output.json

# Convert to Surge format
curl -sL "https://example.com/sub" | subpipe convert -f surge -o output.conf
```

### Generate Template

```bash
# Generate Clash template
subpipe template -f clash -o template.yaml

# Generate Singbox template
subpipe template -f singbox -o template.json

# Generate Surge template
subpipe template -f surge -o template.conf
```

### Use Template with Conversion

```bash
# Use template with placeholders
curl -sL "https://example.com/sub" | subpipe convert -f clash --template template.yaml -o output.yaml
```

## Template Placeholders

Templates support flexible node filtering using placeholders.

### Basic Placeholders

| Placeholder | Description |
|-------------|-------------|
| `{{ALL-TAG}}` | All nodes |

### Include/Exclude Filters

| Placeholder | Description |
|-------------|-------------|
| `{{INCLUDE-TAG:keyword}}` | Include nodes containing keyword |
| `{{EXCLUDE-TAG:keyword}}` | Exclude nodes containing keyword |

### Multiple Keywords

Use comma for OR logic (any keyword matches):

```
{{INCLUDE-TAG:香港,日本}}
```
> Returns nodes containing "香港" OR "日本"

### AND Operator (`&`)

Use `&` when ALL conditions must match:

```
{{INCLUDE-TAG:香港 & 高速}}
```
> Returns nodes containing BOTH "香港" AND "高速"

### OR Operator (`|`)

Use `|` when ANY condition can match:

```
{{INCLUDE-TAG:香港 | 日本}}
```
> Returns nodes containing "香港" OR "日本"

### Combined Filters

Use `;` to combine multiple filters:

```
{{ALL-TAG;EXCLUDE-TAG:住宅}}
```
> All nodes excluding those with "住宅"

### Advanced: Mix AND/OR with Exclude

Use curly braces `{}` to combine different filter types:

```
{{INCLUDE-TAG:香港} & {EXCLUDE-TAG:住宅}}
```
> Nodes with "香港" but NOT "住宅"

```
{{INCLUDE-TAG:香港} | {INCLUDE-TAG:日本}}
```
> Nodes with "香港" OR "日本"

## Template Examples

### Clash Template

```yaml
mixed-port: 7890
mode: rule

proxies: []

proxy-groups:
  - name: 🚀 Select
    type: select
    proxies:
      - '{{ALL-TAG}}'

  - name: 🇭🇰 香港
    type: select
    proxies:
      - '{{INCLUDE-TAG:香港}}'

  - name: 🇯🇵 日本
    type: select
    proxies:
      - '{{INCLUDE-TAG:日本}}'

  - name: 🌐 Global
    type: select
    proxies:
      - '{{EXCLUDE-TAG:香港,台湾}}'

  - name: 🏠 Residential
    type: select
    proxies:
      - '{{INCLUDE-TAG:香港 & 住宅}}'

rules:
  - GEOIP,CN,DIRECT
  - MATCH,🚀 Select
```

### Surge Template

```ini
[General]
loglevel = notify
dns-server = 223.5.5.5, 114.114.114.114

[Proxy]

[Proxy Group]
🚀 Select = select, {{ALL-TAG}}
🇭🇰 香港 = select, {{INCLUDE-TAG:香港}}
🇯🇵 日本 = select, {{INCLUDE-TAG:日本}}
🌐 Global = select, {{EXCLUDE-TAG:香港,台湾}}
🏠 Residential = select, {{INCLUDE-TAG:香港 & 住宅}}

[Rule]
GEOIP,CN,DIRECT
MATCH,🚀 Select
```

## Syntax Summary

| Syntax | Meaning |
|--------|---------|
| `{{ALL-TAG}}` | All nodes |
| `{{INCLUDE-TAG:A,B}}` | Nodes with A or B |
| `{{INCLUDE-TAG:A & B}}` | Nodes with A and B |
| `{{INCLUDE-TAG:A \| B}}` | Nodes with A or B |
| `{{EXCLUDE-TAG:A}}` | Exclude nodes with A |
| `{A} & {EXCLUDE:B}` | A but not B |
| `{A} \| {B}` | A or B |

## License

MIT License
