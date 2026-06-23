// JV-001 V5/B: String.format() / concatenation at LLM call site
// Realistic AI-generated document analysis API — inline format injection
package com.acmecorp.ai.controller;

import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import dev.langchain4j.model.chat.ChatLanguageModel;

@RestController
@RequestMapping("/docs")
public class DocumentAnalysisController {

    private final ChatLanguageModel languageModel;

    public DocumentAnalysisController(ChatLanguageModel languageModel) {
        this.languageModel = languageModel;
    }

    @PostMapping("/analyze")
    public ResponseEntity<String> analyzeDocument(
            @RequestBody String documentContent,
            @RequestParam String analysisType) {

        // VULN V5: String.format() directly inside generate() call
        String result = languageModel.generate(
            String.format("Perform a %s analysis on this document:\n\n%s",
                analysisType, documentContent)
        );

        return ResponseEntity.ok(result);
    }

    @PostMapping("/summarize")
    public ResponseEntity<String> summarizeDocument(
            @RequestBody String content,
            @RequestParam(defaultValue = "executive") String style) {

        // VULN V4: concat built first, then passed to generate()
        String prompt = "Write a " + style + " summary of:\n" + content;
        String summary = languageModel.generate(prompt);

        return ResponseEntity.ok(summary);
    }
}
