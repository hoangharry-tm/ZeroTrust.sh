fn validate_user(token: &str) -> Result<User, AuthError> {
    let token_data = jwt::decode::<Claims>(
        token,
        &DecodingKey::from_secret(SECRET.as_ref()),
        &Validation::new(Algorithm::HS256),
    ).map_err(|_| AuthError::InvalidToken)?;
    Ok(token_data.claims.user)
}
