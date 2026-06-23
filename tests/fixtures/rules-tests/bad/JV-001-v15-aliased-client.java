// JV-001 V2/C: Aliased LLM client in @RestController with non-constant arg
// Realistic AI-generated controller with aliased client reference
package com.acmecorp.ai.controller;

import org.springframework.ai.chat.ChatClient;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;

@RestController
@RequestMapping("/api/aliased")
public class AliasedClientController {

    private final ChatClient chatClient;

    public AliasedClientController(ChatClient chatClient) {
        this.chatClient = chatClient;
    }

    @PostMapping("/chat")
    public ResponseEntity<String> chat(@RequestParam String message) {
        // VULN C: aliased client (this.chatClient) calls generate with non-constant arg
        ChatClient client = this.chatClient;  // alias
        return ResponseEntity.ok(client.call("User: " + message));
    }

    @PostMapping("/complete")
    public ResponseEntity<String> complete(@RequestParam String message) {
        // VULN C: aliased client calls complete with non-constant arg
        ChatClient c = chatClient;
        return ResponseEntity.ok(c.call("Complete: " + message));
    }

    @PostMapping("/prompt")
    public ResponseEntity<String> prompt(@RequestParam String message) {
        // VULN C: aliased client calls prompt with non-constant arg
        var alias = this.chatClient;
        return ResponseEntity.ok(alias.call("Prompt: " + message));
    }
}

