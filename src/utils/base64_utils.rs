//! Base64 utility functions

use base64::{Engine, engine::general_purpose};
use anyhow::Result;

/// Decode Base64 string
pub fn decode(input: &str) -> Result<Vec<u8>> {
    // Try standard Base64
    if let Ok(decoded) = general_purpose::STANDARD.decode(input) {
        return Ok(decoded);
    }
    
    // Try URL-safe Base64
    if let Ok(decoded) = general_purpose::URL_SAFE.decode(input) {
        return Ok(decoded);
    }
    
    // Try with padding
    let padded = add_padding(input);
    general_purpose::STANDARD.decode(&padded)
        .or_else(|_| general_purpose::URL_SAFE.decode(&padded))
        .map_err(|e| anyhow::anyhow!("Base64 decode failed: {}", e))
}

// 暂时未使用的函数
/// Encode bytes to Base64
#[allow(dead_code)]
pub fn encode(data: &[u8]) -> String {
    general_purpose::STANDARD.encode(data)
}

/// Add Base64 padding
fn add_padding(input: &str) -> String {
    let mut padded = input.to_string();
    while padded.len() % 4 != 0 {
        padded.push('=');
    }
    padded
}

// 暂时未使用的函数
/// Try to decode Base64, return original if failed
#[allow(dead_code)]
pub fn try_decode(input: &str) -> String {
    match decode(input) {
        Ok(bytes) => String::from_utf8_lossy(&bytes).to_string(),
        Err(_) => input.to_string(),
    }
}
