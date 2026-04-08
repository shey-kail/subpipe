//! CLI module - command line interface for sublink

use clap::{Parser, ValueEnum};
use std::path::PathBuf;

/// Output format enum
#[derive(Debug, Clone, ValueEnum)]
pub enum OutputFormat {
    Clash,
    Singbox,
    Surge,
}

/// Convert subcommand - converts base64 subscription content to config
#[derive(Parser)]
pub struct ConvertArgs {
    /// Output format (clash, singbox, surge)
    #[arg(short, long, value_enum, default_value = "clash")]
    pub format: OutputFormat,

    /// Input file path (or "-" for stdin)
    #[arg(short, long, default_value = "-")]
    pub input: String,

    /// Output file path (or "-" for stdout)
    #[arg(short, long, default_value = "-")]
    pub output: String,

    /// Template file path (optional, for using custom template)
    #[arg(short, long)]
    pub template: Option<String>,
}

/// Template subcommand - generates a default configuration template
#[derive(Parser)]
pub struct TemplateArgs {
    /// Output format (clash, singbox)
    #[arg(short, long, value_enum, default_value = "clash")]
    pub format: OutputFormat,

    /// Output file path (or "-" for stdout)
    #[arg(short, long, default_value = "-")]
    pub output: String,
}

impl TemplateArgs {
    /// Get output path (None for stdout)
    pub fn output_path(&self) -> Option<PathBuf> {
        if self.output == "-" {
            None
        } else {
            Some(PathBuf::from(&self.output))
        }
    }
}

/// CLI commands
#[derive(Parser)]
#[command(name = "sublink")]
#[command(version = "0.2.2")]
#[command(author = "sheee")]
#[command(about = "A lightweight subscription converter for proxy protocols")]
pub enum Commands {
    /// Convert subscription content to config format
    Convert(ConvertArgs),
    /// Generate a default configuration template
    Template(TemplateArgs),
}

impl ConvertArgs {
    /// Get input path (None for stdin)
    pub fn input_path(&self) -> Option<PathBuf> {
        if self.input == "-" {
            None
        } else {
            Some(PathBuf::from(&self.input))
        }
    }

    /// Get output path (None for stdout)
    pub fn output_path(&self) -> Option<PathBuf> {
        if self.output == "-" {
            None
        } else {
            Some(PathBuf::from(&self.output))
        }
    }
}
