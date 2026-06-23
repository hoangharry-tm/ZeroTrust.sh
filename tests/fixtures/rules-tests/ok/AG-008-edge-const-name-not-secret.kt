// Edge case: const val has "KEY" in name but reads from env, not hardcoded
object Config {
    const val API_KEY_NAME = "OPENAI_API_KEY"
    const val SECRET_NAME = "JWT_SECRET"
    const val DB_PASSWORD_NAME = "DB_PASSWORD"

    val apiKey: String by lazy { System.getenv("OPENAI_API_KEY") ?: "" }
    val jwtSecret: String by lazy { System.getenv("JWT_SECRET") ?: "" }

    // Configuration key names, not actual credentials
    val configKeys = mapOf(
        "api" to API_KEY_NAME,
        "jwt" to SECRET_NAME,
        "db" to DB_PASSWORD_NAME
    )
}

// Enum constants, not credentials
enum class CredentialType {
    API_KEY,
    ACCESS_TOKEN,
    CLIENT_SECRET,
    PASSWORD
}
