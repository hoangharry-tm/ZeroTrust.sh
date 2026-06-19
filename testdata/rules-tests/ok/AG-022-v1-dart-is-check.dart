User? getUserFromRequest(Request request) {
  if (request.body is User) {
    return request.body as User;
  }
  return null;
}

bool validateAuth(JsonMap payload) {
  final token = payload['token'];
  if (token is! String) return false;
  return verify(token, SecretKey(payload['key'] as String));
}
