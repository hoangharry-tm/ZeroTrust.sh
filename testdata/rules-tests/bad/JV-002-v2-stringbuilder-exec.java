// JV-002 V4/C: SQL assembled via StringBuilder then passed to Statement.execute*()
// Realistic AI-generated order management system — dynamic filter builder with injection
package com.acmecorp.orders.repository;

import org.springframework.stereotype.Repository;
import javax.servlet.http.HttpServletRequest;
import java.sql.*;
import java.util.*;

@Repository
public class OrderFilterRepository {

    private final Connection connection;

    public OrderFilterRepository(Connection connection) {
        this.connection = connection;
    }

    public List<Map<String, Object>> filterOrders(HttpServletRequest req) throws SQLException {
        String customerId = req.getParameter("customerId");
        String status = req.getParameter("status");
        String dateFrom = req.getParameter("dateFrom");
        String dateTo = req.getParameter("dateTo");

        // VULN V4: StringBuilder assembles SQL from user input
        StringBuilder sb = new StringBuilder("SELECT * FROM orders WHERE 1=1");

        if (customerId != null && !customerId.isEmpty()) {
            sb.append(" AND customer_id = ").append(customerId);
        }
        if (status != null && !status.isEmpty()) {
            sb.append(" AND status = '").append(status).append("'");
        }
        if (dateFrom != null) {
            sb.append(" AND created_at >= '").append(dateFrom).append("'");
        }
        if (dateTo != null) {
            sb.append(" AND created_at <= '").append(dateTo).append("'");
        }
        sb.append(" ORDER BY created_at DESC LIMIT 100");

        Statement stmt = connection.createStatement();
        ResultSet rs = stmt.executeQuery(sb.toString());  // VULN: StringBuilder result passed to executeQuery

        List<Map<String, Object>> orders = new ArrayList<>();
        while (rs.next()) {
            Map<String, Object> order = new HashMap<>();
            order.put("id", rs.getInt("id"));
            order.put("status", rs.getString("status"));
            order.put("total", rs.getDouble("total"));
            orders.add(order);
        }
        return orders;
    }
}
