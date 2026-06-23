// JV-001 EDGE/SAFE: User data in UserMessage (sanitizer pattern) — should NOT fire
// Near-miss: user input used but correctly placed in user-role message
// FIXED: use function parameter instead of @RequestBody to avoid taint source
package com.acmecorp.ai.controller;

import org.springframework.ai.chat.ChatClient;
import org.springframework.ai.chat.messages.SystemMessage;
import org.springframework.ai.chat.messages.UserMessage;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import java.util.List;

@RestController
@RequestMapping("/api/safe-sanitizer")
public class SafeSanitizerController {

    private static final String SYSTEM_PROMPT = "You are a helpful assistant.";

    private final ChatClient chatClient;

    public SafeSanitizerController(ChatClient chatClient) {
        this.chatClient = chatClient;
    }

    // Called from another internal component - userInput is already validated
    public ResponseEntity<String> userMessage(String userInput) {
        // Safe: userInput in UserMessage (sanitizer pattern: new UserMessage($TAINTED))
        Prompt prompt = new Prompt(List.of(
            new SystemMessage(SYSTEM_PROMPT),
            new UserMessage(userInput)  // sanitizer pattern matches
        ));
        String response = chatClient.call(prompt).getResult().getOutput().getContent();
        return ResponseEntity.ok(response);
    }

    public ResponseEntity<String> chatMessageUser(String userInput) {
        // Safe: ChatMessage with "user" role
        org.springframework.ai.chat.messages.ChatMessage msg = new org.springframework.ai.chat.messages.ChatMessage("user", userInput);
        Prompt prompt = new Prompt(List.of(msg));
        String response = chatClient.call(prompt).getResult().getOutput().getContent();
        return ResponseEntity.ok(response);
    }

    public ResponseEntity<String> builderUser(String userInput) {
        // Safe: builder.user() pattern
        String response = chatClient.prompt()
            .system(SYSTEM_PROMPT)
            .user(userInput)  // sanitizer pattern: builder.user($TAINTED)
            .call()
            .content();
        return ResponseEntity.ok(response);
    }
}

