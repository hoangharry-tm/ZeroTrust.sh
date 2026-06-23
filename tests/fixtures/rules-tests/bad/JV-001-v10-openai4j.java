// JV-001 V9/A: openai4j ChatCompletion / complete() as sink
// Realistic AI-generated service using openai4j
package com.acmecorp.ai.service;

import com.openai4j.chat.ChatCompletion;
import com.openai4j.chat.ChatCompletionRequest;
import com.openai4j.completion.Completion;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;

@Service
public class OpenAi4jService {

    private final ChatCompletion chatCompletion;
    private final Completion completion;

    public OpenAi4jService(ChatCompletion chatCompletion, Completion completion) {
        this.chatCompletion = chatCompletion;
        this.completion = completion;
    }

    @PostMapping("/openai-chat")
    public ResponseEntity<String> openaiChat(@RequestParam String userMessage) {
        // VULN: openai4j createChatCompletion with user message
        ChatCompletionRequest request = ChatCompletionRequest.builder()
            .model("gpt-3.5-turbo")
            .messages(List.of(new ChatCompletionRequest.Message("user", userMessage)))
            .build();
        String response = chatCompletion.createChatCompletion(request).getChoices().get(0).getMessage().getContent();
        return ResponseEntity.ok(response);
    }

    @PostMapping("/openai-complete")
    public ResponseEntity<String> openaiComplete(@RequestParam String prompt) {
        // VULN: openai4j complete() with user prompt
        String response = completion.complete(prompt);
        return ResponseEntity.ok(response);
    }
}

