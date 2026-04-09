//! Template interpolation parser
//!
//! Supported formats:
//! - `{{ALL-TAG}}` - Insert all nodes
//! - `{{INCLUDE-TAG:keyword1 & keyword2}}` - Include nodes matching ALL keywords (AND)
//! - `{{INCLUDE-TAG:keyword1 | keyword2}}` - Include nodes matching ANY keyword (OR)
//! - `{{INCLUDE-TAG:keyword1,keyword2}}` - Include nodes matching ANY keyword (OR, legacy)
//! - `{{EXCLUDE-TAG:keyword1 & keyword2}}` - Exclude nodes matching ALL keywords (AND)
//! - `{{EXCLUDE-TAG:keyword1 | keyword2}}` - Exclude nodes matching ANY keyword (OR)
//! - `{{ALL-TAG;INCLUDE-TAG:香港 & 高速}}` - Combined: all nodes filtered by AND condition
//!
//! Examples:
//! - `{{INCLUDE-TAG:香港 & 高速}}` - Nodes with BOTH "香港" and "高速"
//! - `{{INCLUDE-TAG:香港 | 日本}}` - Nodes with EITHER "香港" or "日本"
//! - `{{INCLUDE-TAG:香港} & {EXCLUDE-TAG:高速}}` - Nodes with "香港" but NOT "高速"
//! - `{{INCLUDE-TAG:香港} | {INCLUDE-TAG:高速}}` - Nodes with "香港" OR "高速"

use anyhow::{bail, Result};

/// Filter operator
#[derive(Debug, Clone, PartialEq)]
pub enum FilterOperator {
    And,
    Or,
}

/// A single filter condition
#[derive(Debug, Clone, PartialEq)]
pub struct FilterCondition {
    pub operator: FilterOperator,
    pub keywords: Vec<String>,
}

/// Interpolation rule types
#[derive(Debug, Clone, PartialEq)]
pub enum InterpolationRule {
    /// Insert all nodes
    AllTag,
    /// Include/exclude filter with operator
    Filter {
        include: bool,          // true for INCLUDE, false for EXCLUDE
        conditions: Vec<FilterCondition>,
    },
    /// Combined rules (multiple filters applied sequentially)
    Combined {
        all_tag: bool,
        filters: Vec<(bool, Vec<FilterCondition>)>, // (is_include, conditions)
    },
}

/// Parser for interpolation rules
pub struct InterpolationParser;

impl InterpolationParser {
    /// Parse interpolation rule string
    pub fn parse(rule: &str) -> Result<InterpolationRule> {
        let rule = rule.trim();

        // Extract rule content (remove double braces)
        if !rule.starts_with("{{") || !rule.ends_with("}}") {
            bail!(
                "Interpolation rule must be wrapped with {{}}: {}",
                rule
            );
        }

        let rule_expr: &str = &rule[2..rule.len() - 2];

        if rule_expr.trim().is_empty() {
            bail!("Empty interpolation rule");
        }

        Self::parse_rule_expression(rule_expr)
    }

    /// Parse rule expression (without braces)
    fn parse_rule_expression(rule_expr: &str) -> Result<InterpolationRule> {
        let rule_expr = rule_expr.trim();

        // First, check if there are top-level & or | operators between rule blocks
        // e.g., `INCLUDE-TAG:香港} & {EXCLUDE-TAG:高速` or `INCLUDE-TAG:香港} | {INCLUDE-TAG:高速`
        // We need to find & or | that are NOT inside braces

        // Try to find top-level operators
        if let Some((left, op, right)) = Self::find_top_level_operator(rule_expr) {
            // Parse the left and right parts recursively
            let left_rule = Self::parse_single_rule(left.trim())?;
            let right_rule = Self::parse_single_rule(right.trim())?;

            // Combine the two rules
            return Self::combine_rules(&left_rule, &right_rule, op);
        }

        // Split by semicolon for combined rules
        let parts: Vec<&str> = rule_expr
            .split(';')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();

        if parts.is_empty() {
            bail!("Empty interpolation rule");
        }

        if parts.len() == 1 {
            return Self::parse_single_rule(parts[0]);
        }

        // Multiple parts - combined rule
        let mut all_tag = false;
        let mut filters: Vec<(bool, Vec<FilterCondition>)> = Vec::new();

        for part in parts {
            if part.is_empty() {
                continue;
            }

            // Check for ALL-TAG
            let part_upper = part.to_uppercase();
            if part_upper == "ALL-TAG" {
                all_tag = true;
                continue;
            }
            if part_upper.starts_with("ALL-TAG:") {
                all_tag = true;
                continue;
            }

            // Parse INCLUDE-TAG or EXCLUDE-TAG
            if part_upper.starts_with("INCLUDE-TAG:") {
                let conditions = Self::parse_filter_conditions(part, "INCLUDE-TAG")?;
                filters.push((true, conditions)); // true = include
            } else if part_upper.starts_with("EXCLUDE-TAG:") {
                let conditions = Self::parse_filter_conditions(part, "EXCLUDE-TAG")?;
                filters.push((false, conditions)); // false = exclude
            } else {
                bail!("Unknown interpolation rule: {}", part);
            }
        }

        if filters.is_empty() && !all_tag {
            bail!("Invalid interpolation rule");
        }

        Ok(InterpolationRule::Combined {
            all_tag,
            filters,
        })
    }

    /// Find top-level & or | operator (between rule blocks)
    fn find_top_level_operator(expr: &str) -> Option<(&str, char, &str)> {
        // Look for patterns like `} & {` or `} | {` which indicate
        // a top-level operator between two complete rule blocks

        // Find } & {
        if let Some(and_pos) = expr.find("} & {") {
            // left: expr[..and_pos], right: expr[and_pos + 5..] (skip "} & {")
            let left = expr[..and_pos].trim();
            let right = expr[and_pos + 5..].trim();
            return Some((left, '&', right));
        }

        // Find } | {
        if let Some(or_pos) = expr.find("} | {") {
            // left: expr[..or_pos], right: expr[or_pos + 5..] (skip "} | {")
            let left = expr[..or_pos].trim();
            let right = expr[or_pos + 5..].trim();
            return Some((left, '|', right));
        }

        None
    }

    /// Combine two rules with an operator
    fn combine_rules(left: &InterpolationRule, right: &InterpolationRule, op: char) -> Result<InterpolationRule> {
        // First, convert both rules to filters
        let left_filter = Self::rule_to_filter(left)?;
        let right_filter = Self::rule_to_filter(right)?;

        match op {
            '&' => {
                // AND: both conditions must be satisfied
                // We create two separate filters that will be applied sequentially
                Ok(InterpolationRule::Combined {
                    all_tag: true,
                    filters: vec![left_filter, right_filter],
                })
            }
            '|' => {
                // OR: either condition can be satisfied
                // For OR, we need to combine the keywords into a single OR condition
                // Only works if both sides are the same type (both include or both exclude)
                if left_filter.0 != right_filter.0 {
                    bail!("Cannot mix INCLUDE and EXCLUDE in OR expression")
                }

                let is_include = left_filter.0;
                let mut combined_keywords: Vec<String> = Vec::new();

                for condition in &left_filter.1 {
                    combined_keywords.extend(condition.keywords.iter().cloned());
                }
                for condition in &right_filter.1 {
                    combined_keywords.extend(condition.keywords.iter().cloned());
                }

                Ok(InterpolationRule::Filter {
                    include: is_include,
                    conditions: vec![FilterCondition {
                        operator: FilterOperator::Or,
                        keywords: combined_keywords,
                    }],
                })
            }
            _ => bail!("Unknown operator: {}", op),
        }
    }

    /// Convert a rule to a filter tuple
    fn rule_to_filter(rule: &InterpolationRule) -> Result<(bool, Vec<FilterCondition>)> {
        match rule {
            InterpolationRule::AllTag => {
                // AllTag doesn't contribute to filtering in AND/OR context
                bail!("ALL-TAG cannot be used in AND/OR expression")
            }
            InterpolationRule::Filter { include, conditions } => {
                Ok((*include, conditions.clone()))
            }
            InterpolationRule::Combined { all_tag, filters } => {
                if *all_tag && filters.len() == 1 {
                    return Ok(filters[0].clone());
                }
                bail!("Complex combined rules cannot be used in AND/OR expression")
            }
        }
    }

    /// Parse a single rule (without semicolons)
    fn parse_single_rule(rule: &str) -> Result<InterpolationRule> {
        let rule = rule.trim();
        let rule_upper = rule.to_uppercase();

        if rule_upper == "ALL-TAG" {
            return Ok(InterpolationRule::AllTag);
        }

        if rule_upper.starts_with("INCLUDE-TAG:") {
            let conditions = Self::parse_filter_conditions(rule, "INCLUDE-TAG")?;
            return Ok(InterpolationRule::Filter {
                include: true,
                conditions,
            });
        }

        if rule_upper.starts_with("EXCLUDE-TAG:") {
            let conditions = Self::parse_filter_conditions(rule, "EXCLUDE-TAG")?;
            return Ok(InterpolationRule::Filter {
                include: false,
                conditions,
            });
        }

        if rule_upper.starts_with("ALL-TAG:") {
            return Ok(InterpolationRule::AllTag);
        }

        bail!("Unknown interpolation rule: {}", rule)
    }

    /// Parse filter conditions with AND/OR operators
    /// Supports:
    /// - `keyword1,keyword2` - OR (legacy, comma-separated)
    /// - `keyword1 | keyword2` - OR (pipe-separated)
    /// - `keyword1 & keyword2` - AND (ampersand-separated)
    fn parse_filter_conditions(rule: &str, rule_type: &str) -> Result<Vec<FilterCondition>> {
        let rule_upper = rule.to_uppercase();
        let rule_type_upper = rule_type.to_uppercase();

        let colon_pos = rule_upper.find(&format!("{}:", rule_type_upper));
        if colon_pos.is_none() {
            bail!("{} requires keyword parameters", rule_type);
        }

        let keywords_str = &rule[colon_pos.unwrap() + rule_type.len() + 1..];
        if keywords_str.trim().is_empty() {
            bail!("{} requires at least one keyword", rule_type);
        }

        // Check for & (AND) operator first
        if keywords_str.contains('&') {
            // Parse as AND conditions (all keywords must match)
            let keywords: Vec<String> = keywords_str
                .split('&')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();

            if keywords.is_empty() {
                bail!("{} requires at least one keyword", rule_type);
            }

            return Ok(vec![FilterCondition {
                operator: FilterOperator::And,
                keywords,
            }]);
        }

        // Check for | (OR) operator
        if keywords_str.contains('|') {
            // Parse as OR conditions (any keyword matches)
            let keywords: Vec<String> = keywords_str
                .split('|')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();

            if keywords.is_empty() {
                bail!("{} requires at least one keyword", rule_type);
            }

            return Ok(vec![FilterCondition {
                operator: FilterOperator::Or,
                keywords,
            }]);
        }

        // Legacy: comma-separated means OR
        let keywords: Vec<String> = keywords_str
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        if keywords.is_empty() {
            bail!("{} requires at least one keyword", rule_type);
        }

        Ok(vec![FilterCondition {
            operator: FilterOperator::Or, // comma = OR
            keywords,
        }])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_tag() {
        let result = InterpolationParser::parse("{{ALL-TAG}}").unwrap();
        assert_eq!(result, InterpolationRule::AllTag);
    }

    #[test]
    fn test_include_tag_or() {
        let result = InterpolationParser::parse("{{INCLUDE-TAG:香港,日本}}").unwrap();
        match result {
            InterpolationRule::Filter { include, conditions } => {
                assert!(include);
                assert_eq!(conditions.len(), 1);
                assert_eq!(conditions[0].operator, FilterOperator::Or);
                assert_eq!(conditions[0].keywords, vec!["香港", "日本"]);
            }
            _ => panic!("Expected Filter"),
        }
    }

    #[test]
    fn test_include_tag_and() {
        let result = InterpolationParser::parse("{{INCLUDE-TAG:香港 & 高速}}").unwrap();
        match result {
            InterpolationRule::Filter { include, conditions } => {
                assert!(include);
                assert_eq!(conditions.len(), 1);
                assert_eq!(conditions[0].operator, FilterOperator::And);
                assert_eq!(conditions[0].keywords, vec!["香港", "高速"]);
            }
            _ => panic!("Expected Filter"),
        }
    }

    #[test]
    fn test_include_tag_or_pipe() {
        let result = InterpolationParser::parse("{{INCLUDE-TAG:香港 | 日本}}").unwrap();
        match result {
            InterpolationRule::Filter { include, conditions } => {
                assert!(include);
                assert_eq!(conditions.len(), 1);
                assert_eq!(conditions[0].operator, FilterOperator::Or);
                assert_eq!(conditions[0].keywords, vec!["香港", "日本"]);
            }
            _ => panic!("Expected Filter"),
        }
    }

    #[test]
    fn test_exclude_tag_or() {
        let result = InterpolationParser::parse("{{EXCLUDE-TAG:低速 | 过期}}").unwrap();
        match result {
            InterpolationRule::Filter { include, conditions } => {
                assert!(!include);
                assert_eq!(conditions[0].operator, FilterOperator::Or);
                assert_eq!(conditions[0].keywords, vec!["低速", "过期"]);
            }
            _ => panic!("Expected Filter"),
        }
    }

    #[test]
    fn test_combined_all_with_filter() {
        let result = InterpolationParser::parse("{{ALL-TAG;INCLUDE-TAG:香港 & 高速}}").unwrap();
        match result {
            InterpolationRule::Combined { all_tag, filters } => {
                assert!(all_tag);
                assert_eq!(filters.len(), 1);
                assert!(filters[0].0); // is_include
                assert_eq!(filters[0].1[0].operator, FilterOperator::And);
            }
            _ => panic!("Expected Combined"),
        }
    }
}
