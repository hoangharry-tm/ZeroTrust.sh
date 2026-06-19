fn validate_session(session_id: &str) -> Result<User, Error> {
    let conn = db_pool.get()?;
    let user = conn.query_one("SELECT * FROM users WHERE session = $1", &[session_id])?;
    Ok(user)
}
