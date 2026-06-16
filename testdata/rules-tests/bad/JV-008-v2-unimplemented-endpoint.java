// JV-008 V9/D: TODO in @RequestMapping controller returning null/UOE
// Realistic AI-generated payment controller — unimplemented security-critical endpoints
package com.acmecorp.payment;

import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;

@RestController
@RequestMapping("/api/payment")
public class PaymentController {

    // VULN D: @PostMapping with TODO + return null
    @PostMapping("/refund")
    public ResponseEntity<?> processRefund(
            @RequestBody RefundRequest request,
            @RequestParam String authToken) {
        // TODO: implement refund authorization and processing
        return null;  // VULN: unimplemented endpoint returns null
    }

    // VULN D: @DeleteMapping with FIXME + throws UOE
    @DeleteMapping("/subscription/{id}")
    public ResponseEntity<?> cancelSubscription(@PathVariable Long id) {
        // FIXME: cancellation service not yet connected
        throw new UnsupportedOperationException("cancelSubscription not implemented");  // VULN
    }

    // VULN D: @PutMapping with TODO + return null
    @PutMapping("/limits")
    public ResponseEntity<?> updateSpendingLimits(@RequestBody Object limits) {
        // TODO: validate and apply spending limits
        return null;  // VULN: TODO + return null in @PutMapping
    }
}
