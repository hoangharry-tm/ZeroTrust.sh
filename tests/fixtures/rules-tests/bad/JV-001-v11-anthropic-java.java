// JV-001 V9/A: Anthropic Java SDK messages().create() as sink
// Realistic AI-generated service using Anthropic Java SDK
package com.acmecorp.ai.service;

import com.anthropic.client.okhttp.AnthropicClientOkHttp;
import com.anthropic.models.messages.MessageCreateParams;
import com.anthropic.models.messages.Message;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;

@Service
public class AnthropicService {

    private final AnthropicClientOkHttp client;

    public AnthropicService(AnthropicClientOkHttp client) {
        this.client = client;
    }

    @PostMapping("/anthropic-chat")
    public ResponseEntity<String> anthropicChat(@RequestParam String userMessage) {
        // VULN: Anthropic messages().create() with user message
        MessageCreateParams params = MessageCreateParams.builder()
            .model("claude-3-haiku-20240307")
            .maxTokens(1024)
            .messages(List.of(new MessageCreateParams.Message("user", userMessage)))
            .build();
        Message response = client.messages().create(params);
        return ResponseEntity.ok(response.getContent().get(0).getText());
    }
}

