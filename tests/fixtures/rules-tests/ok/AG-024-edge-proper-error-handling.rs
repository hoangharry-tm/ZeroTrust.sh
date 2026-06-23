// AG-024 EDGE/SAFE: proper error handling instead of unwrap/expect/unwrap_or
use std::fs;

fn read_config(path: &str) -> Result<String, String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read config: {}", e))?;
    Ok(content)
}

fn validate_user(username: &str) -> Result<bool, String> {
    let user = find_user(username)
        .ok_or_else(|| "User not found".to_string())?;
    Ok(user)
}

fn authenticate(token: &str) -> Result<bool, String> {
    verify_token(token)
        .map_err(|_| "Token verification failed".to_string())
}

fn find_user(name: &str) -> Option<bool> {
    Some(name.len() > 3)
}

fn verify_token(t: &str) -> Result<bool, String> {
    Ok(t.len() > 10)
}
