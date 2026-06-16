// JV-003 EDGE/SAFE: EntityManager.createQuery() with completely static JPQL string
// Near-miss: createQuery() used but with zero string concatenation
package com.acmecorp.maintenance;

import org.springframework.stereotype.Component;
import javax.persistence.*;
import java.util.List;

@Component
public class DatabaseStatisticsService {

    @PersistenceContext
    private EntityManager em;

    /**
     * Count active products — completely static JPQL, no user input.
     * Used by monitoring/health endpoint.
     */
    public long countActiveProducts() {
        // Safe: single static string literal, no concatenation
        return em.createQuery("SELECT COUNT(p) FROM Product p WHERE p.active = true", Long.class)
                 .getSingleResult();
    }

    public List<?> getAllActiveCategories() {
        // Safe: static JPQL with no user data
        return em.createQuery(
            "SELECT DISTINCT p.category FROM Product p WHERE p.active = true ORDER BY p.category"
        ).getResultList();
    }
}
