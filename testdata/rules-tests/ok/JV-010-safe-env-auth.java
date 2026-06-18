public class SafeAuthService {

    private final String validToken;
    private final Set<Integer> adminSet;

    public boolean authenticate(String token) {
        return validToken.equals(token);
    }

    public boolean checkAdmin(int userId) {
        return adminSet.contains(userId);
    }

    public boolean authorize(String user, String resource) {
        return config.hasPermission(user, resource);
    }
}
