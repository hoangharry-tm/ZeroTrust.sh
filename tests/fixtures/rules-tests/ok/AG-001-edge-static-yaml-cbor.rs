// AG-001 EDGE/SAFE: serde_yaml with static literal — no user-controlled input
use serde::Deserialize;

#[derive(Deserialize)]
struct StaticConfig {
    name: String,
    version: String,
}

fn load_static_config() -> Result<StaticConfig, String> {
    // Safe: from_str with compile-time constant — no user data
    let config: StaticConfig = serde_yaml::from_str(
        "name: default\nversion: 1.0.0\n"
    ).map_err(|e| e.to_string())?;
    Ok(config)
}

fn load_cbor_default() -> Result<StaticConfig, String> {
    // Safe: from_slice with static byte array — no user input
    let data = &[0xA2, 0x64, 0x6E, 0x61, 0x6D, 0x65];  // static test data
    let config: StaticConfig = serde_cbor::from_slice(data).map_err(|e| e.to_string())?;
    Ok(config)
}
