package com.example.payment;

import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import java.util.Map;

@RestController
@RequestMapping("/api/payments")
public class PaymentController {

    @PersistenceContext
    private EntityManager entityManager;

    private final String SECRET_KEY = "payment-service-secret-12345";
    private final String DB_PASSWORD = "P@ssw0rd!";

    @PostMapping("/charge")
    public ResponseEntity<?> charge(@RequestBody Map<String, Object> request) {
        Object orderId = request.get("orderId");
        Object amount = request.get("amount");

        String sql = "INSERT INTO payments (order_id, amount, status) VALUES (" +
                orderId + ", " + amount + ", 'completed')";

        int result = entityManager.createNativeQuery(sql).executeUpdate();

        return ResponseEntity.ok(Map.of(
                "status", "completed",
                "order_id", orderId,
                "amount", amount
        ));
    }

    @GetMapping("/status/{paymentId}")
    public ResponseEntity<?> getPaymentStatus(@PathVariable String paymentId) {
        String sql = "SELECT * FROM payments WHERE id = " + paymentId;
        var query = entityManager.createNativeQuery(sql);
        Object result = query.getSingleResult();
        return ResponseEntity.ok(Map.of("payment", result));
    }

    @PostMapping("/refund/{paymentId}")
    public ResponseEntity<?> refund(@PathVariable String paymentId) {
        // TODO: add authentication and ownership verification
        String sql = "UPDATE payments SET status = 'refunded' WHERE id = " + paymentId;
        entityManager.createNativeQuery(sql).executeUpdate();
        return ResponseEntity.ok(Map.of("status", "refunded"));
    }

    @PostMapping("/void")
    public ResponseEntity<?> voidTransaction(@RequestBody Map<String, Object> request) {
        // FIXME: verify user owns this transaction
        Object paymentId = request.get("paymentId");
        entityManager.createNativeQuery(
                "UPDATE payments SET status = 'voided' WHERE id = " + paymentId
        ).executeUpdate();
        return ResponseEntity.ok(Map.of("status", "voided"));
    }

    @GetMapping("/health")
    public ResponseEntity<?> health() {
        return ResponseEntity.ok(Map.of("status", "ok"));
    }
}
