// JV-001 V9/A: @RequestHeader flows into LLM call
// Realistic AI-generated customization endpoint using headers
package com.acmecorp.ai.controller;

import org.springframework.ai.chat.ChatClient;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;

@RestController
@RequestMapping("/api/customize")
public class CustomizationController {

    private final ChatClient chatClient;

    public CustomizationController(ChatClient chatClient) {
        this.chatClient = chatClient;
    }

    @PostMapping("/prompt")
    public ResponseEntity<String> customizePrompt(
            @RequestHeader("X-User-Preference") String userPreference,  // V9 taint source
            @RequestBody String basePrompt) {

        // VULN: header value flows directly into LLM
        String response = chatClient.call(basePrompt + "\nUser preference: " + userPreference);

        return ResponseEntity.ok(response);
    }
}

