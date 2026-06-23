// AG-001 EDGE/SAFE: serde_json::from_str called with a static string literal — excluded
use serde_json::Value;

/// This uses only static literal JSON — the rule excludes literal string arguments.
fn load_default_config() -> Value {
    // Safe: literal string argument — excluded by rule's `not` clause
    serde_json::from_str(r#"{
        "timeout_seconds": 30,
        "max_retries": 3,
        "log_level": "info"
    }"#).expect("Default config is valid JSON")
}

fn get_empty_schema() -> Value {
    // Safe: literal — excluded
    serde_json::from_str("{}").unwrap()
}

fn main() {
    let config = load_default_config();
    println!("Config: {:?}", config);
}
