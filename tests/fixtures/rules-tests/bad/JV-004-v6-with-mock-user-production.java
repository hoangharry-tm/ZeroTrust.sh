// JV-004 V/D: @WithMockUser(roles="ADMIN") outside test infrastructure
// Realistic AI-generated controller with @WithMockUser in production code
package com.acmecorp.admin;

import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;

@RestController
@RequestMapping("/api/admin")
public class AdminController {

    // VULN D: @WithMockUser in non-test class (no @SpringBootTest / @ExtendWith)
    @WithMockUser(roles = "ADMIN")
    @GetMapping("/users")
    public ResponseEntity<String> listUsers() {
        // This should be real auth, not mock user
        return ResponseEntity.ok("user list");
    }

    // VULN D: also on this method — mock user in production code
    @WithMockUser(roles = "ADMIN")
    @PostMapping("/settings")
    public ResponseEntity<String> updateSettings(@RequestBody String settings) {
        return ResponseEntity.ok("updated");
    }
}
