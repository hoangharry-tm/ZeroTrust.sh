// JV-003 V1/B: EntityManager.createQuery() with String concatenation — JPQL injection
// Realistic AI-generated reporting module — dynamic JPQL built from user filters
package com.acmecorp.reporting.repository;

import org.springframework.stereotype.Repository;
import org.springframework.web.bind.annotation.RequestParam;
import javax.persistence.*;
import java.util.*;

@Repository
public class ReportRepository {

    @PersistenceContext
    private EntityManager em;

    public List<Object[]> getProductSalesByCategory(
            String category,
            String dateFrom,
            String dateTo) {

        // VULN: String concat directly in createQuery()
        List result = em.createQuery(
            "SELECT p.category, SUM(oi.quantity), SUM(oi.total) " +
            "FROM OrderItem oi JOIN oi.product p " +
            "WHERE p.category = '" + category + "' " +
            "AND oi.order.createdAt BETWEEN '" + dateFrom + "' AND '" + dateTo + "' " +
            "GROUP BY p.category"
        ).getResultList();

        return result;
    }

    public List getCustomerOrders(String customerId, String statusFilter) {
        // VULN: StringBuilder then createNativeQuery()
        StringBuilder jpql = new StringBuilder("SELECT o FROM Order o WHERE o.customer.id = ");
        jpql.append(customerId);
        if (statusFilter != null && !statusFilter.isEmpty()) {
            jpql.append(" AND o.status = '").append(statusFilter).append("'");
        }

        return em.createQuery(jpql.toString()).getResultList();  // VULN: StringBuilder result
    }
}
