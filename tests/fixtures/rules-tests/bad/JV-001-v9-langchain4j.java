// JV-001 V9/A: LangChain4J ChatLanguageModel.generate() / chat() as sink
// Realistic AI-generated service using LangChain4J
package com.acmecorp.ai.service;

import dev.langchain4j.model.chat.ChatLanguageModel;
import dev.langchain4j.data.message.UserMessage;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;

@Service
public class LangChain4jService {

    private final ChatLanguageModel languageModel;

    public LangChain4jService(ChatLanguageModel languageModel) {
        this.languageModel = languageModel;
    }

    @PostMapping("/langchain-generate")
    public ResponseEntity<String> langchainGenerate(@RequestParam String prompt) {
        // VULN: ChatLanguageModel.generate() with user prompt
        String response = languageModel.generate(prompt);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/langchain-chat")
    public ResponseEntity<String> langchainChat(@RequestParam String userMessage) {
        // VULN: ChatLanguageModel.chat() with user message
        String response = languageModel.chat(UserMessage.from(userMessage)).content();
        return ResponseEntity.ok(response);
    }
}

