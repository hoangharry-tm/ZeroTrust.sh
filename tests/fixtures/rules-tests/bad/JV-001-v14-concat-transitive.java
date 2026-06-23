// JV-001 V4/B: Transitive concatenation - variable built then passed to LLM
// Realistic AI-generated service showing concat then pass pattern
package com.acmecorp.ai.service;

import org.springframework.ai.chat.ChatClient;
import dev.langchain4j.model.chat.ChatLanguageModel;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;

@Service
public class ConcatTransitiveService {

    private final ChatClient chatClient;
    private final ChatLanguageModel languageModel;

    public ConcatTransitiveService(ChatClient chatClient, ChatLanguageModel languageModel) {
        this.chatClient = chatClient;
        this.languageModel = languageModel;
    }

    @PostMapping("/concat-generate")
    public ResponseEntity<String> concatGenerate(@RequestParam String userInput) {
        // VULN V4: concat built first, then passed to generate()
        String prompt = "Analyze: " + userInput + " for security issues";
        return ResponseEntity.ok(languageModel.generate(prompt));
    }

    @PostMapping("/concat-complete")
    public ResponseEntity<String> concatComplete(@RequestParam String userInput) {
        // VULN V4: concat then complete()
        String prompt = "Complete: " + userInput;
        return ResponseEntity.ok(languageModel.generate(prompt));
    }

    @PostMapping("/concat-prompt")
    public ResponseEntity<String> concatPrompt(@RequestParam String userInput) {
        // VULN V4: concat then prompt()
        String prompt = "User said: " + userInput;
        return ResponseEntity.ok(chatClient.call(prompt));
    }

    @PostMapping("/concat-call")
    public ResponseEntity<String> concatCall(@RequestParam String userInput) {
        // VULN V4: concat then call()
        String prompt = "Process: " + userInput;
        return ResponseEntity.ok(chatClient.call(prompt));
    }
}

