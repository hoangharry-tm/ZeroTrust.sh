// AG-001 V1: serde_json::from_str with unvalidated function parameter
// Realistic AI-generated webhook processor — deserialization without validation
use serde_json::Value;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
struct WebhookPayload {
    event_type: String,
    data: Value,
    timestamp: u64,
}

/// Process an incoming webhook payload from external source.
/// WARNING: input is not validated before deserialization.
pub fn process_webhook(raw_body: &str) -> Result<WebhookPayload, Box<dyn std::error::Error>> {
    // VULN V1: serde_json::from_str on unvalidated input parameter
    let payload: WebhookPayload = serde_json::from_str(raw_body)?;
    Ok(payload)
}

/// Parse user-submitted configuration.
pub fn parse_user_config(config_json: &str) -> Result<Value, serde_json::Error> {
    // VULN V1: from_str on user-controlled input
    serde_json::from_str(config_json)
}

/// Parse byte slice from HTTP body.
pub fn from_bytes(body: &[u8]) -> Result<Value, serde_json::Error> {
    // VULN V1: from_slice on unvalidated bytes
    serde_json::from_slice(body)
}

/// Parse YAML configuration from user upload.
pub fn parse_yaml_config(yaml_content: &str) -> Result<Value, serde_yaml::Error> {
    // VULN V7: serde_yaml::from_str — same risk class
    serde_yaml::from_str(yaml_content)
}

fn main() {
    let test_input = r#"{"event_type": "order.created", "data": {}, "timestamp": 1234567890}"#;
    match process_webhook(test_input) {
        Ok(payload) => println!("Processed: {:?}", payload),
        Err(e) => eprintln!("Error: {}", e),
    }
}
