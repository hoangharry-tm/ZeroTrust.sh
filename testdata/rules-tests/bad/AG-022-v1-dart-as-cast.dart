User getUserFromRequest(Request request) {
  final user = request.body as User;
  return user;
}

bool validateAuth(JsonMap payload) {
  final token = payload['token'] as String;
  final key = payload['key'] as SecretKey;
  return verify(token, key);
}
