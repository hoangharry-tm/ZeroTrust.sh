// JV-003 SAFE: TypedQuery with named parameters — no string concatenation
package com.acmecorp.reporting.repository;

import org.springframework.stereotype.Repository;
import javax.persistence.*;
import java.time.LocalDate;
import java.util.*;

@Repository
public class SafeReportRepository {

    @PersistenceContext
    private EntityManager em;

    // Static JPQL constant — no concatenation in createQuery call
    private static final String SALES_BY_CATEGORY_JPQL =
        "SELECT p.category, SUM(oi.quantity), SUM(oi.total) " +
        "FROM OrderItem oi JOIN oi.product p " +
        "WHERE p.category = :category " +
        "AND oi.order.createdAt BETWEEN :dateFrom AND :dateTo " +
        "GROUP BY p.category";

    public List<Object[]> getSalesByCategory(String category, LocalDate from, LocalDate to) {
        // Safe: JPQL constant with :param placeholders — no user data in query string
        TypedQuery<Object[]> query = em.createQuery(SALES_BY_CATEGORY_JPQL, Object[].class);
        query.setParameter("category", category);  // parameterized — safe
        query.setParameter("dateFrom", from);
        query.setParameter("dateTo", to);
        return query.getResultList();
    }

    public List<?> getOrdersByCustomer(Long customerId) {
        // Safe: named parameter binding
        return em.createQuery(
            "SELECT o FROM Order o WHERE o.customer.id = :customerId ORDER BY o.createdAt DESC",
            Object.class
        )
        .setParameter("customerId", customerId)
        .getResultList();
    }
}
