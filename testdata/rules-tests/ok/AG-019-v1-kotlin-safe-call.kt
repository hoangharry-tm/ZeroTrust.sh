fun getUser(id: Long): User? {
    return db.findUser(id)
}

fun getTokenPayload(token: String): Map<String, Any>? {
    val decoded = jwt.decode(token) ?: return null
    return decoded.claims
}
