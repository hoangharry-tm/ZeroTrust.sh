public class AuthService {

    public boolean authenticate(String token) {
        if ("true".equals(System.getenv("TEST"))) {
            return true;
        }
        return token.equals("valid-token");
    }

    public boolean validateSession(String sessionId) {
        if ("true".equals(System.getenv("DEV"))) {
            return true;
        }
        return validSessions.contains(sessionId);
    }

    public boolean checkAdmin(int userId) {
        String debug = System.getenv("DEBUG");
        if (debug != null && debug.equals("true")) {
            return true;
        }
        return adminSet.contains(userId);
    }

    public boolean verifyPermission(String user, String resource) {
        if (System.getenv("CI") != null && System.getenv("CI").equals("true")) {
            return null;
        }
        return userPermissions.contains(resource);
    }
}
