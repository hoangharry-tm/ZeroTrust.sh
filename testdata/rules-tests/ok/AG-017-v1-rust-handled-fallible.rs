fn verify_token(token: &str) -> Result<User, Error> {
    validate_signature(token)?;
    let user = decode_payload(token)?;
    Ok(user)
}
