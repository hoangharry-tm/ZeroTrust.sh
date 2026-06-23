// JV-002 EDGE/SAFE: Statement.executeQuery() with a fully static SQL string
// Near-miss: uses Statement (not PreparedStatement) but with zero user data
package com.acmecorp.maintenance;

import org.springframework.stereotype.Component;
import java.sql.*;
import java.util.*;

@Component
public class DatabaseHealthChecker {

    private final Connection connection;

    public DatabaseHealthChecker(Connection connection) {
        this.connection = connection;
    }

    /**
     * Health check — only static SQL, no user input touches the query.
     * Called by an internal health endpoint, not by user-controlled parameters.
     */
    public Map<String, Object> checkDatabaseHealth() throws SQLException {
        Statement stmt = connection.createStatement();

        // Safe: fully static string literal — no user data involved at all
        ResultSet rs = stmt.executeQuery("SELECT COUNT(*) as cnt FROM products WHERE active = TRUE");

        Map<String, Object> health = new HashMap<>();
        if (rs.next()) {
            health.put("active_products", rs.getInt("cnt"));
        }
        health.put("status", "healthy");
        return health;
    }

    public int countPendingOrders() throws SQLException {
        Statement stmt = connection.createStatement();
        // Safe: completely static SQL string
        ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM orders WHERE status = 'PENDING'");
        return rs.next() ? rs.getInt(1) : 0;
    }
}
