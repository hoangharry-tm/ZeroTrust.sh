// JV-001 V9/A: @RequestParam flows into Spring AI LLM call
// Realistic AI-generated customer support controller — prompt injection via URL param
package com.acmecorp.support.controller;

import org.springframework.ai.chat.ChatClient;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;

@RestController
@RequestMapping("/api/support")
public class SupportChatController {

    private final ChatClient chatClient;

    public SupportChatController(ChatClient chatClient) {
        this.chatClient = chatClient;
    }

    @PostMapping("/chat")
    public ResponseEntity<String> handleChat(
            @RequestParam String userMessage,      // V9 taint source
            @RequestParam(defaultValue = "general") String topic) {

        String systemContext = "You are a helpful support agent for AcmeCorp. Topic: " + topic;

        // VULN: userMessage flows directly into chat prompt via call()
        String promptText = systemContext + "\nUser: " + userMessage;
        String response = chatClient.call(promptText);  // taint sink

        return ResponseEntity.ok(response);
    }

    @GetMapping("/quick-answer")
    public ResponseEntity<String> quickAnswer(@RequestParam String question) {
        // VULN: direct flow from @RequestParam to generate()
        return ResponseEntity.ok(chatClient.prompt().user(question).call().content());
    }
}
