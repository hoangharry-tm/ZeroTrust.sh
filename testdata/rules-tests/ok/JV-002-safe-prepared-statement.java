// JV-002 SAFE: PreparedStatement with parameterized queries — correct pattern
package com.acmecorp.catalog.repository;

import org.springframework.stereotype.Repository;
import org.springframework.web.bind.annotation.RequestParam;
import javax.servlet.http.HttpServletRequest;
import java.sql.*;
import java.util.*;

@Repository
public class SafeProductRepository {

    private final Connection connection;

    public SafeProductRepository(Connection connection) {
        this.connection = connection;
    }

    public List<Map<String, Object>> searchProducts(
            String name, String category, double minPrice) throws SQLException {

        // Safe: static SQL with ? placeholders — no user data in the SQL string
        String sql = "SELECT id, name, price, category FROM products " +
                     "WHERE name LIKE ? AND category = ? AND price >= ?";

        PreparedStatement pstmt = connection.prepareStatement(sql);
        pstmt.setString(1, "%" + name + "%");
        pstmt.setString(2, category);
        pstmt.setDouble(3, minPrice);

        ResultSet rs = pstmt.executeQuery();  // Safe: parameterized

        List<Map<String, Object>> results = new ArrayList<>();
        while (rs.next()) {
            Map<String, Object> row = new HashMap<>();
            row.put("id", rs.getInt("id"));
            row.put("name", rs.getString("name"));
            row.put("price", rs.getDouble("price"));
            results.add(row);
        }
        return results;
    }

    public Optional<Map<String, Object>> findById(int productId) throws SQLException {
        // Safe: single placeholder, static SQL
        PreparedStatement pstmt = connection.prepareStatement(
            "SELECT * FROM products WHERE id = ?"
        );
        pstmt.setInt(1, productId);
        ResultSet rs = pstmt.executeQuery();

        if (rs.next()) {
            Map<String, Object> product = new HashMap<>();
            product.put("id", rs.getInt("id"));
            product.put("name", rs.getString("name"));
            return Optional.of(product);
        }
        return Optional.empty();
    }
}
