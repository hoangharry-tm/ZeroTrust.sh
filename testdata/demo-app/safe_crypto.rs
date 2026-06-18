use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

#[derive(Deserialize, Serialize, Debug)]
struct Config {
    version: u32,
    name: String,
    settings: Settings,
}

#[derive(Deserialize, Serialize, Debug)]
struct Settings {
    endpoint: String,
    timeout: u32,
}

fn load_config_safe(path: impl AsRef<Path>) -> Result<Config, Box<dyn std::error::Error>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let config: Config = serde_json::from_reader(reader)?;
    Ok(config)
}

fn validate_config(config: &Config) -> Result<(), String> {
    if config.version == 0 {
        return Err("invalid version".into());
    }
    if config.name.is_empty() {
        return Err("name required".into());
    }
    if config.settings.endpoint.is_empty() {
        return Err("endpoint required".into());
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config_safe("/etc/app/config.json")?;
    validate_config(&config)?;
    println!("Config loaded: {}", config.name);
    Ok(())
}
