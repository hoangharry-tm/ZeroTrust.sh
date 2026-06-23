// JV-001 EDGE/SAFE: Constant prompt with no user data — should NOT fire
// Near-miss: LLM called but prompt is fully static
package com.acmecorp.ai.service;

import org.springframework.ai.chat.ChatClient;
import org.springframework.stereotype.Service;

@Service
public class ConstantPromptService {

    private static final String STATIC_PROMPT =
        "Generate a summary of our Q2 2026 financial results. Focus on revenue growth and key metrics.";

    private final ChatClient chatClient;

    public ConstantPromptService(ChatClient chatClient) {
        this.chatClient = chatClient;
    }

    // Called from scheduled job — no user input
    public String generateScheduledReport() {
        // Safe: prompt is entirely static constant
        return chatClient.call(STATIC_PROMPT);
    }

    public String generateStaticChat() {
        // Safe: prompt is string literal
        return chatClient.call("What is the capital of France?");
    }
}

