// JV-001 V9/A: @RequestBody flows into Spring AI LLM call
// Realistic AI-generated document analysis endpoint — prompt injection via request body
package com.acmecorp.ai.controller;

import org.springframework.ai.chat.ChatClient;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;

@RestController
@RequestMapping("/api/docs")
public class DocumentAnalysisController {

    private final ChatClient chatClient;

    public DocumentAnalysisController(ChatClient chatClient) {
        this.chatClient = chatClient;
    }

    @PostMapping("/analyze")
    public ResponseEntity<String> analyze(
            @RequestBody String documentText,      // V9 taint source
            @RequestParam String analysisType) {

        // VULN: documentText flows directly into chat prompt via call()
        String promptText = "Analyze this document (" + analysisType + "):\n" + documentText;
        String response = chatClient.call(promptText);  // taint sink

        return ResponseEntity.ok(response);
    }
}

