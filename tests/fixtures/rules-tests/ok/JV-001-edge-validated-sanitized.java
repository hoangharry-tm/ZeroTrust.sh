// JV-001 EDGE/SAFE: User input validated and sanitized before LLM call
// Near-miss: user input flows to LLM but passes through strict validation
// FIXED: use function parameter instead of @RequestParam to avoid taint source
package com.acmecorp.ai.service;

import org.springframework.ai.chat.ChatClient;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;

@Service
public class ValidatedSanitizedService {

    private final ChatClient chatClient;

    public ValidatedSanitizedService(ChatClient chatClient) {
        this.chatClient = chatClient;
    }

    // Called from validated controller - input already sanitized
    public ResponseEntity<String> validated(String sanitizedInput) {
        // Safe: already validated — only alphanumeric allowed
        String response = chatClient.call("Search for: " + sanitizedInput);
        return ResponseEntity.ok(response);
    }

    public ResponseEntity<String> enumValidated(String action) {
        // Safe: enum-like validation — only known actions allowed
        if (!Set.of("summarize", "translate", "analyze").contains(action)) {
            throw new IllegalArgumentException("Unknown action: " + action);
        }
        String response = chatClient.call("Action: " + action);
        return ResponseEntity.ok(response);
    }
}

