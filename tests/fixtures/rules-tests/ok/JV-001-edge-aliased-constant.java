// JV-001 EDGE/SAFE: Aliased client but constant argument — should NOT fire Rule C
// Near-miss: aliased client reference but argument is string literal
package com.acmecorp.ai.controller;

import org.springframework.ai.chat.ChatClient;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;

@RestController
@RequestMapping("/api/safe-aliased")
public class SafeAliasedController {

    private final ChatClient chatClient;

    public SafeAliasedController(ChatClient chatClient) {
        this.chatClient = chatClient;
    }

    @PostMapping("/constant")
    public ResponseEntity<String> constantArg() {
        // Safe: aliased client but constant argument
        ChatClient client = this.chatClient;
        return ResponseEntity.ok(client.call("Fixed prompt: generate report"));
    }

    // Called from internal service - reportType already validated
    public ResponseEntity<String> enumSwitch(String reportType) {
        // Safe: argument derived from validated enum, not raw user input
        String prompt;
        switch (reportType) {
            case "sales": prompt = "Generate sales report"; break;
            case "engineering": prompt = "Generate engineering report"; break;
            default: throw new IllegalArgumentException("Invalid type");
        }
        ChatClient c = chatClient;
        return ResponseEntity.ok(c.call(prompt));  // Constant-ish after validation
    }
}

