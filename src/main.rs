//! Sublink Worker - A lightweight subscription converter for proxy protocols
//!
//! This is a Rust implementation that provides a simple CLI for converting
//! base64 subscription content to clash/singbox/surge configurations.

mod builders;
mod cli;
mod parsers;
mod templates;
mod utils;

use anyhow::{Context, Result};
use clap::Parser;
use cli::{Commands, ConvertArgs, OutputFormat, TemplateArgs};
use std::io::{self, Read};
use templates::InterpolationParser;
use templates::interpolation::{InterpolationRule, FilterOperator};


/// Read input from file or stdin
fn read_input(args: &ConvertArgs) -> Result<String> {
    if let Some(path) = args.input_path() {
        std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read input file: {}", path.display()))
    } else {
        let mut input = String::new();
        io::stdin().read_to_string(&mut input)?;
        Ok(input)
    }
}

/// Write output to file or stdout
fn write_output_content(path: Option<&std::path::PathBuf>, content: &str) -> Result<()> {
    if let Some(p) = path {
        std::fs::write(p, content)
            .with_context(|| format!("Failed to write output file: {}", p.display()))
    } else {
        println!("{}", content);
        Ok(())
    }
}

/// Convert base64 content to the specified format
fn convert(args: &ConvertArgs) -> Result<String> {
    let input = read_input(args)?;

    // Try to decode Base64 content
    let decoded_content = if let Ok(decoded) = crate::utils::base64_utils::decode(&input) {
        String::from_utf8_lossy(&decoded).to_string()
    } else {
        input
    };

    // Normalize line endings (CRLF -> LF)
    let normalized_content = decoded_content.replace("\r\n", "\n").replace("\r", "\n");

    // Parse all proxy URLs
    let mut proxies = Vec::new();
    for line in normalized_content.lines() {
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            if let Ok(proxy) = parsers::ProxyParser::parse(trimmed) {
                proxies.push(proxy);
            }
        }
    }

    if proxies.is_empty() {
        anyhow::bail!("No valid proxy URLs found in input");
    }

    // Use template.json as default for Singbox format
    let template_path = if let Some(ref path) = args.template {
        Some(path.clone())
    } else if matches!(args.format, OutputFormat::Singbox) {
        Some("template.json".to_string())
    } else {
        None
    };

    // If a template is specified or using default template.json for Singbox, use template-based generation
    if let Some(ref path) = template_path {
        if std::path::Path::new(path).exists() {
            let template_content = std::fs::read_to_string(path)
                .with_context(|| format!("Failed to read template file: {}", path))?;
            return apply_template(&args.format, &template_content, &proxies);
        }
    }

    // Otherwise use simple generation
    match args.format {
        OutputFormat::Clash => {
            let config = builders::build_simple_clash(&proxies);
            serde_yaml::to_string(&config)
                .context("Failed to serialize Clash config")
        }
        OutputFormat::Singbox => {
            let config = builders::build_simple_singbox(&proxies);
            serde_json::to_string_pretty(&config)
                .context("Failed to serialize Singbox config")
        }
        OutputFormat::Surge => {
            Ok(builders::build_simple_surge(&proxies))
        }
    }
}

/// Filter proxies based on interpolation rule
fn filter_proxies_by_rule<'a>(
    proxies: &'a [parsers::ProxyConfig],
    rule: &InterpolationRule,
) -> Vec<&'a parsers::ProxyConfig> {
    match rule {
        InterpolationRule::AllTag => {
            // Return all proxies
            proxies.iter().collect()
        }
        InterpolationRule::Filter { include, conditions } => {
            // Apply filter with AND/OR conditions
            let mut result: Vec<&parsers::ProxyConfig> = proxies.iter().collect();

            for condition in conditions {
                let matched: Vec<&parsers::ProxyConfig> = if *include {
                    // Include: keep proxies that match
                    result
                        .iter()
                        .filter(|p| {
                            let name_lower = p.name().to_lowercase();
                            match condition.operator {
                                FilterOperator::And => {
                                    condition.keywords.iter().all(|k| name_lower.contains(&k.to_lowercase()))
                                }
                                FilterOperator::Or => {
                                    condition.keywords.iter().any(|k| name_lower.contains(&k.to_lowercase()))
                                }
                            }
                        })
                        .cloned()
                        .collect()
                } else {
                    // Exclude: remove proxies that match
                    result
                        .iter()
                        .filter(|p| {
                            let name_lower = p.name().to_lowercase();
                            match condition.operator {
                                FilterOperator::And => {
                                    !condition.keywords.iter().all(|k| name_lower.contains(&k.to_lowercase()))
                                }
                                FilterOperator::Or => {
                                    !condition.keywords.iter().any(|k| name_lower.contains(&k.to_lowercase()))
                                }
                            }
                        })
                        .cloned()
                        .collect()
                };
                result = matched;
            }

            result
        }
        InterpolationRule::Combined { all_tag, filters } => {
            // Start with all proxies if all_tag is true, otherwise start with empty
            let mut result: Vec<&parsers::ProxyConfig> = if *all_tag {
                proxies.iter().collect()
            } else {
                proxies.iter().collect() // Start with all, then filter down
            };

            // Apply each filter in sequence
            for (is_include, conditions) in filters {
                for condition in conditions {
                    let filtered: Vec<&parsers::ProxyConfig> = if *is_include {
                        // Include: keep proxies that match
                        result
                            .iter()
                            .filter(|p| {
                                let name_lower = p.name().to_lowercase();
                                match condition.operator {
                                    FilterOperator::And => {
                                        condition.keywords.iter().all(|k| name_lower.contains(&k.to_lowercase()))
                                    }
                                    FilterOperator::Or => {
                                        condition.keywords.iter().any(|k| name_lower.contains(&k.to_lowercase()))
                                    }
                                }
                            })
                            .cloned()
                            .collect()
                    } else {
                        // Exclude: remove proxies that match
                        result
                            .iter()
                            .filter(|p| {
                                let name_lower = p.name().to_lowercase();
                                match condition.operator {
                                    FilterOperator::And => {
                                        !condition.keywords.iter().all(|k| name_lower.contains(&k.to_lowercase()))
                                    }
                                    FilterOperator::Or => {
                                        !condition.keywords.iter().any(|k| name_lower.contains(&k.to_lowercase()))
                                    }
                                }
                            })
                            .cloned()
                            .collect()
                    };
                    result = filtered;
                }
            }

            result
        }
    }
}

/// Find and process interpolation placeholders in a string
fn find_placeholders(s: &str) -> Vec<(String, String)> {
    let mut results = Vec::new();
    let mut search_start = 0;

    while let Some(start) = s[search_start..].find("{{") {
        let start = search_start + start;
        if let Some(end) = s[start..].find("}}") {
            let end = start + end;
            let placeholder = s[start..end + 2].to_string();
            let content = s[start + 2..end].to_string();
            results.push((placeholder, content));
            search_start = end + 2;
        } else {
            break;
        }
    }

    results
}

/// Apply template to proxies - replace interpolation placeholders with actual proxy names
fn apply_template(format: &OutputFormat, template: &str, proxies: &[parsers::ProxyConfig]) -> Result<String> {
    // Find all placeholders in the template
    let placeholders = find_placeholders(template);

    // For YAML formats (Clash), we need to parse and manipulate the structure
    if matches!(format, OutputFormat::Clash) {
        return apply_clash_template_with_placeholders(template, proxies, &placeholders);
    }

    // For JSON formats (Singbox), process template with placeholders
    if matches!(format, OutputFormat::Singbox) {
        // Parse the template as JSON and replace placeholders
        let mut config: serde_json::Value = serde_json::from_str(template)
            .context("Failed to parse template JSON")?;

        // Build a map from placeholder content to resolved names
        let mut content_to_names: std::collections::HashMap<String, Vec<serde_json::Value>> = std::collections::HashMap::new();

        for (placeholder, content) in &placeholders {
            let rule = InterpolationParser::parse(&format!("{{{{{}}}}}", content));
            let names: Vec<serde_json::Value> = if let Ok(rule) = rule {
                let filtered = filter_proxies_by_rule(proxies, &rule);
                filtered.iter().map(|p| serde_json::Value::String(p.name().to_string())).collect()
            } else {
                Vec::new()
            };
            content_to_names.insert(content.clone(), names.clone());
            content_to_names.insert(placeholder.clone(), names);
        }

        // Add proxy nodes as outbounds at the beginning
        let proxy_outbounds: Vec<serde_json::Value> = proxies.iter().map(|p| p.to_singbox()).collect();

        // Process outbounds array
        if let Some(outbounds) = config.get_mut("outbounds").and_then(|v| v.as_array_mut()) {
            // First, insert proxy outbounds at the beginning
            for (i, proxy) in proxy_outbounds.into_iter().enumerate() {
                outbounds.insert(i, proxy);
            }

            // Then process existing outbounds, replacing placeholders
            for outbound in outbounds.iter_mut() {
                if let Some(obj) = outbound.as_object_mut() {
                    if let Some(outbounds_field) = obj.get_mut("outbounds") {
                        if let Some(arr) = outbounds_field.as_array_mut() {
                            // Collect indices and names to replace
                            let mut to_replace: Vec<(usize, Vec<serde_json::Value>)> = Vec::new();
                            for (i, item) in arr.iter().enumerate() {
                                if let Some(s) = item.as_str() {
                                    for (key, names) in &content_to_names {
                                        if s.contains(key) || key.contains(s) {
                                            to_replace.push((i, names.clone()));
                                            break;
                                        }
                                    }
                                }
                            }
                            // Replace in reverse order to maintain indices
                            for (i, names) in to_replace.into_iter().rev() {
                                // Remove the placeholder element
                                arr.remove(i);
                                // Insert the resolved names at the same position
                                for (j, name) in names.into_iter().enumerate() {
                                    arr.insert(i + j, name);
                                }
                            }
                        }
                    }
                }
            }

            // First pass: identify outbounds to remove and collect their tags
            let tags_to_remove: std::collections::HashSet<String> = outbounds.iter()
                .filter_map(|o| {
                    if let Some(obj) = o.as_object() {
                        let tag = obj.get("tag").and_then(|v| v.as_str()).unwrap_or("");
                        let out_type = obj.get("type").and_then(|v| v.as_str()).unwrap_or("");
                        // Skip DIRECT, REJECT, direct, block
                        if tag == "DIRECT" || tag == "REJECT" || out_type == "direct" || out_type == "block" {
                            return None;
                        }
                        if let Some(arr) = obj.get("outbounds").and_then(|v| v.as_array()) {
                            if arr.is_empty() {
                                return Some(tag.to_string());
                            }
                        }
                    }
                    None
                })
                .collect();

            // Remove outbounds with empty arrays (except DIRECT and REJECT)
            outbounds.retain(|o| {
                if let Some(obj) = o.as_object() {
                    let tag = obj.get("tag").and_then(|v| v.as_str()).unwrap_or("");
                    let out_type = obj.get("type").and_then(|v| v.as_str()).unwrap_or("");
                    // Keep DIRECT, REJECT, and outbounds with non-empty arrays
                    if tag == "DIRECT" || tag == "REJECT" || out_type == "direct" || out_type == "block" {
                        return true;
                    }
                    if let Some(arr) = obj.get("outbounds").and_then(|v| v.as_array()) {
                        return !arr.is_empty();
                    }
                }
                true
            });

            // Second pass: remove references to deleted tags from remaining outbounds
            for outbound in outbounds.iter_mut() {
                if let Some(obj) = outbound.as_object_mut() {
                    if let Some(outbounds_field) = obj.get_mut("outbounds") {
                        if let Some(arr) = outbounds_field.as_array_mut() {
                            arr.retain(|item| {
                                if let Some(s) = item.as_str() {
                                    !tags_to_remove.contains(s)
                                } else {
                                    true
                                }
                            });
                        }
                    }
                }
            }
        }

        return serde_json::to_string_pretty(&config)
            .context("Failed to serialize Singbox config");
    }

    // For other formats (Surge), use simple string replacement
    if matches!(format, OutputFormat::Surge) {
        let mut result = template.to_string();

        // Replace placeholders in proxy groups
        for (placeholder, content) in &placeholders {
            let rule = InterpolationParser::parse(&format!("{{{{{}}}}}", content));
            if let Ok(rule) = rule {
                let filtered = filter_proxies_by_rule(proxies, &rule);
                let names: Vec<String> = filtered.iter().map(|p| p.name().to_string()).collect();
                let replacement = names.join(", ");
                result = result.replace(placeholder, &replacement);
            }
        }

        // Add proxy nodes to [Proxy] section
        // Find the [Proxy] section and add proxies after it
        if let Some(proxy_idx) = result.find("[Proxy]") {
            let after_proxy = &result[proxy_idx..];
            if let Some(newline_idx) = after_proxy[7..].find('\n') {
                let insert_pos = proxy_idx + 7 + newline_idx + 1;
                let proxy_lines: Vec<String> = proxies.iter().map(|p| builders::surge_proxy_line(p)).collect();
                let proxy_section = proxy_lines.join("\n") + "\n";
                result.insert_str(insert_pos, &proxy_section);

                // Remove placeholder lines (lines containing only the placeholder comment)
                result = result.lines()
                    .filter(|line| !line.trim().starts_with('#') || !line.contains("proxies"))
                    .collect::<Vec<_>>()
                    .join("\n");
            }
        }

        return Ok(result);
    }

    let mut result = template.to_string();
    for (placeholder, content) in &placeholders {
        let rule = InterpolationParser::parse(&format!("{{{{{}}}}}", content));
        if let Ok(rule) = rule {
            let filtered: Vec<&parsers::ProxyConfig> = filter_proxies_by_rule(proxies, &rule);
            let names: Vec<String> = filtered.iter().map(|p| p.name().to_string()).collect();
            let replacement = names.join(", ");
            result = result.replace(placeholder, &replacement);
        }
    }

    Ok(result)
}

/// Apply Clash template with proper YAML list handling and placeholders
fn apply_clash_template_with_placeholders(
    template: &str,
    proxies: &[parsers::ProxyConfig],
    placeholders: &[(String, String)],
) -> Result<String> {
    use serde_yaml::Value;

    // Parse the template
    let mut config: Value = serde_yaml::from_str(template)
        .context("Failed to parse template YAML")?;

    // Build a map from content (without braces) to resolved names
    let mut content_to_names: std::collections::HashMap<String, Vec<Value>> = std::collections::HashMap::new();

    for (placeholder, content) in placeholders {
        let rule = InterpolationParser::parse(&format!("{{{{{}}}}}", content));

        let names: Vec<Value> = if let Ok(rule) = rule {
            let filtered = filter_proxies_by_rule(proxies, &rule);
            filtered.iter().map(|p| Value::String(p.name().to_string())).collect()
        } else {
            // If parsing fails, use empty list
            Vec::new()
        };

        // Store by content (without braces) so we can match with or without quotes
        content_to_names.insert(content.clone(), names.clone());
        // Also store the full placeholder (with braces)
        content_to_names.insert(placeholder.clone(), names);
    }

    // Build proxy list from all nodes (not filtered)
    let proxy_list: Vec<Value> = proxies.iter().map(|p| p.to_clash()).collect();

    // Insert proxies into config
    if let Some(map) = config.as_mapping_mut() {
        map.insert(
            Value::String("proxies".to_string()),
            Value::Sequence(proxy_list),
        );

        // Handle proxy-groups
        if let Some(proxy_groups) = map.get_mut("proxy-groups").and_then(|v| v.as_sequence_mut()) {
            for group in proxy_groups {
                if let Some(group_map) = group.as_mapping_mut() {
                    if let Some(proxies_field) = group_map.get_mut("proxies") {
                        if let Some(proxies_array) = proxies_field.as_sequence_mut() {
                            // First pass: collect placeholder positions and their replacements
                            let mut replacements: Vec<(usize, Value)> = Vec::new();
                            for (i, item) in proxies_array.iter().enumerate() {
                                if let Some(s) = item.as_str() {
                                    // Try to find the content in our map
                                    // The string might be quoted, so we need to find a match
                                    for (key, names) in &content_to_names {
                                        if s.contains(key) || key.contains(s) {
                                            replacements.push((i, Value::Sequence(names.clone())));
                                            break;
                                        }
                                    }
                                }
                            }
                            // Second pass: apply replacements
                            for (i, new_value) in replacements {
                                proxies_array[i] = new_value;
                            }
                        }
                    }
                }
            }
        }
    }

    serde_yaml::to_string(&config)
        .context("Failed to serialize Clash config")
}

/// Handle template generation command
fn generate_template(args: &TemplateArgs) -> Result<String> {
    match args.format {
        OutputFormat::Clash => Ok(templates::generate_clash_template()),
        OutputFormat::Singbox => Ok(templates::generate_singbox_template()),
        OutputFormat::Surge => Ok(templates::generate_surge_template()),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("sublink=info".parse()?)
        )
        .init();

    let args = cli::Commands::parse();

    match args {
        Commands::Convert(convert_args) => {
            let output = convert(&convert_args)?;
            write_output_content(convert_args.output_path().as_ref(), &output)?;
        }
        Commands::Template(template_args) => {
            let output = generate_template(&template_args)?;
            write_output_content(template_args.output_path().as_ref(), &output)?;
        }
    }

    Ok(())
}
