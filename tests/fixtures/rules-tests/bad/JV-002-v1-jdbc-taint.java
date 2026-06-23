// JV-002 V1/A: HTTP request data → JDBC Statement.executeQuery() via concat
// Realistic AI-generated product search endpoint — SQL injection via concat
package com.acmecorp.catalog.repository;

import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.Repository;
import javax.servlet.http.HttpServletRequest;
import java.sql.*;
import java.util.*;

@Repository
public class ProductSearchRepository {

    private final Connection connection;

    public ProductSearchRepository(Connection connection) {
        this.connection = connection;
    }

    /**
     * Search products by name and category.
     * WARNING: this implementation is vulnerable to SQL injection.
     */
    public List<Map<String, Object>> searchProducts(HttpServletRequest request) throws SQLException {
        String name = request.getParameter("name");         // V1 taint source
        String category = request.getParameter("category"); // V1 taint source
        String minPrice = request.getParameter("minPrice");

        Statement stmt = connection.createStatement();

        // VULN: tainted params concatenated directly into SQL query
        String sql = "SELECT id, name, price, category FROM products WHERE " +
                     "name LIKE '%" + name + "%' " +
                     "AND category = '" + category + "' " +
                     "AND price >= " + minPrice;

        ResultSet rs = stmt.executeQuery(sql);  // SQL injection sink

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
}
