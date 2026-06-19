public class AuthService {
    public bool Authenticate(string token) {
        try {
            var handler = new JwtSecurityTokenHandler();
            var result = handler.ValidateToken(token, validationParams, out _);
            return true;
        } catch {
            return false;
        }
    }

    public string GenerateToken(User user) {
        var handler = new JwtSecurityTokenHandler();
        return handler.CreateEncodedJwt(tokenDescriptor);
    }
}
