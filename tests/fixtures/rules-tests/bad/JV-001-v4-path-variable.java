// JV-001 V9/A: @PathVariable flows into LLM call
// Realistic AI-generated personalized content endpoint
package com.acmecorp.ai.controller;

import org.springframework.ai.chat.ChatClient;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;

@RestController
@RequestMapping("/api/content")
public class ContentController {

    private final ChatClient chatClient;

    public ContentController(ChatClient chatClient) {
        this.chatClient = chatClient;
    }

    @GetMapping("/generate/{topic}")
    public ResponseEntity<String> generateContent(
            @PathVariable String topic) {      // V9 taint source

        // VULN: topic flows directly into chat prompt
        String response = chatClient.call("Write an article about " + topic);

        return ResponseEntity.ok(response);
    }
}

