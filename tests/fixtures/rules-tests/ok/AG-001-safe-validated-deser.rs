// AG-001 SAFE: validation before serde deserialization — should NOT fire
use serde_json::Value;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
struct SafePayload {
    event_type: String,
    data: Value,
}

/// Validate input size and structure before deserializing.
fn validate(input: &str) -> Result<(), String> {
    if input.len() > 1_048_576 {  // 1MB limit
        return Err("Payload too large".to_string());
    }
    if !input.trim_start().starts_with('{') {
        return Err("Expected JSON object".to_string());
    }
    Ok(())
}

/// Safe: validate() called (without ?) before from_str — rule excludes this scope
pub fn safe_parse_webhook(raw_body: &str) -> Result<SafePayload, Box<dyn std::error::Error>> {
    // Call validate without ? so ast-grep can match validate($INPUT) directly
    if let Err(e) = validate(raw_body) {
        return Err(e.into());
    }
    let payload: SafePayload = serde_json::from_str(raw_body)?;
    Ok(payload)
}

/// Safe: literal string (not a variable) — excluded by rule
pub fn parse_static_config() -> Value {
    serde_json::from_str(r#"{"version": "1.0", "debug": false}"#).unwrap()
}

fn main() {
    match safe_parse_webhook(r#"{"event_type":"test","data":{}}"#) {
        Ok(p) => println!("{:?}", p),
        Err(e) => eprintln!("{}", e),
    }
}
