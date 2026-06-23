// JV-001 V9/A: spring-ai ChatModel.call() / generate() as sink
// Realistic AI-generated service using ChatModel directly
package com.acmecorp.ai.service;

import org.springframework.ai.chat.ChatClient;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.chat.messages.Message;
import org.springframework.ai.chat.messages.UserMessage;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import java.util.List;

@Service
public class ChatModelService {

    private final ChatModel chatModel;

    public ChatModelService(ChatModel chatModel) {
        this.chatModel = chatModel;
    }

    @PostMapping("/chat-model-call")
    public ResponseEntity<String> chatModelCall(@RequestParam String userText) {
        // VULN: ChatModel.call() with user data in message
        Message userMsg = new UserMessage(userText);
        String response = chatModel.call(new Prompt(List.of(userMsg))).getResult().getOutput().getContent();
        return ResponseEntity.ok(response);
    }

    @PostMapping("/chat-model-generate")
    public ResponseEntity<String> chatModelGenerate(@RequestParam String userText) {
        // VULN: ChatModel.generate() with user data
        String response = chatModel.generate(userText);
        return ResponseEntity.ok(response);
    }
}

