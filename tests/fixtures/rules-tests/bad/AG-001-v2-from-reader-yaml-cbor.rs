// AG-001 V5/V7: serde_json::from_reader, serde_yaml, serde_cbor variants
use serde::Deserialize;
use std::io::Read;

#[derive(Deserialize)]
struct Config {
    url: String,
    timeout: u64,
}

fn deserialize_from_reader<R: Read>(reader: R) -> Result<Config, String> {
    // VULN: from_reader with unvalidated input
    let config: Config = serde_json::from_reader(reader).map_err(|e| e.to_string())?;
    Ok(config)
}

fn deserialize_yaml(input: &str) -> Result<Config, String> {
    // VULN: serde_yaml::from_str with unvalidated input
    let config: Config = serde_yaml::from_str(input).map_err(|e| e.to_string())?;
    Ok(config)
}

fn deserialize_yaml_slice(data: &[u8]) -> Result<Config, String> {
    // VULN: serde_yaml::from_slice with unvalidated input
    let config: Config = serde_yaml::from_slice(data).map_err(|e| e.to_string())?;
    Ok(config)
}

fn deserialize_cbor(data: &[u8]) -> Result<Config, String> {
    // VULN: serde_cbor::from_slice with unvalidated input
    let config: Config = serde_cbor::from_slice(data).map_err(|e| e.to_string())?;
    Ok(config)
}
