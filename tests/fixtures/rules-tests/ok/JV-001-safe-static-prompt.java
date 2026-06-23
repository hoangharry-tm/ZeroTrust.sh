// JV-001 SAFE: user data structurally separated — passed as dedicated user message
// Static system message, user data isolated in user-role message
package com.acmecorp.ai.controller;

import org.springframework.ai.chat.ChatClient;
import org.springframework.ai.chat.messages.SystemMessage;
import org.springframework.ai.chat.messages.UserMessage;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import java.util.List;

@RestController
@RequestMapping("/api/safe-chat")
public class SafeChatController {

    private static final String STATIC_SYSTEM_PROMPT =
        "You are a helpful customer support agent for AcmeCorp products. " +
        "Answer questions professionally. Do not discuss competitors.";

    private final ChatClient chatClient;

    public SafeChatController(ChatClient chatClient) {
        this.chatClient = chatClient;
    }

    @PostMapping("/message")
    public ResponseEntity<String> handleMessage(
            @RequestBody String userMessage) {

        // Safe: system prompt is static, user data in separate user-role message
        Prompt prompt = new Prompt(List.of(
            new SystemMessage(STATIC_SYSTEM_PROMPT),
            new UserMessage(userMessage)  // structurally separated
        ));

        // nosemgrep: JV-001-spring-boot-prompt-injection-taint — user data correctly isolated in UserMessage role, not in system prompt
        String response = chatClient.call(prompt).getResult().getOutput().getContent();
        return ResponseEntity.ok(response);
    }
}
