// AG-024 V2/V3: .expect() and .unwrap_or() in security context
use std::fs;

fn read_config(path: &str) -> String {
    // VULN: expect() in security-critical config load
    let content = fs::read_to_string(path)
        .expect("config file must be readable");
    content
}

fn validate_user(username: &str) -> bool {
    // VULN: unwrap_or with permissive default in security function
    let user = find_user(username)
        .unwrap_or(true);  // VULN: permissive default
    user
}

fn authenticate(token: &str) -> bool {
    // VULN: unwrap_or returning true (bypass)
    verify_token(token)
        .unwrap_or(true)  // VULN: authentication bypass
}

fn find_user(name: &str) -> Option<bool> {
    Some(name.len() > 3)
}

fn verify_token(t: &str) -> Option<bool> {
    Some(t.len() > 10)
}
