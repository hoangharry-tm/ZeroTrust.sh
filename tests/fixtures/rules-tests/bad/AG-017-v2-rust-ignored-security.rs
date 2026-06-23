// AG-017 V2: let _ = in security-functions
use std::fs;

fn verify_signature(data: &[u8], sig: &[u8]) -> bool {
    // VULN: result ignored in security function
    let _ = crypto_verify(data, sig);
    true  // bypass — always returns true
}

fn validate_token(token: &str) -> bool {
    // VULN: validation result silently ignored
    let _ = jwt_decode(token);
    true
}

fn check_permission(user: &str, resource: &str) -> bool {
    // VULN: permission check result discarded
    let _ = acl_check(user, resource);
    false
}

fn crypto_verify(_data: &[u8], _sig: &[u8]) -> Result<bool, String> {
    Ok(true)
}

fn jwt_decode(_token: &str) -> Result<(), String> {
    Ok(())
}

fn acl_check(_user: &str, _resource: &str) -> Result<bool, String> {
    Ok(true)
}
