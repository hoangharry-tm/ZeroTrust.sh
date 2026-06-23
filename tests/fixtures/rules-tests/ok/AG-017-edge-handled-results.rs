// AG-017 EDGE/SAFE: error handling with match instead of let _ =
fn verify_signature(data: &[u8], sig: &[u8]) -> Result<bool, String> {
    // Safe: result is handled with match, not ignored
    match crypto_verify(data, sig) {
        Ok(valid) => Ok(valid),
        Err(e) => Err(format!("Crypto verification failed: {}", e)),
    }
}

fn validate_token(token: &str) -> Result<bool, String> {
    // Safe: result is propagated
    let valid = jwt_decode(token)?;
    Ok(valid)
}

fn crypto_verify(_data: &[u8], _sig: &[u8]) -> Result<bool, String> {
    Ok(true)
}

fn jwt_decode(_token: &str) -> Result<bool, String> {
    Ok(true)
}
