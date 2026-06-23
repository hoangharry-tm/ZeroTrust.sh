// JV-001 V7/A: Generic LLM sink verbs (generate, complete, prompt, ask, infer)
// Realistic AI-generated wrapper with various LLM client method names
package com.acmecorp.ai.service;

import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;

@Service
public class GenericLlmWrapper {

    private final LlmClientWrapper llmClient;

    public GenericLlmWrapper(LlmClientWrapper llmClient) {
        this.llmClient = llmClient;
    }

    @PostMapping("/generate")
    public ResponseEntity<String> generate(@RequestParam String input) {
        // VULN: generate() with user input
        return ResponseEntity.ok(llmClient.generate(input));
    }

    @PostMapping("/complete")
    public ResponseEntity<String> complete(@RequestParam String input) {
        // VULN: complete() with user input
        return ResponseEntity.ok(llmClient.complete(input));
    }

    @PostMapping("/prompt")
    public ResponseEntity<String> prompt(@RequestParam String input) {
        // VULN: prompt() with user input
        return ResponseEntity.ok(llmClient.prompt(input));
    }

    @PostMapping("/ask")
    public ResponseEntity<String> ask(@RequestParam String input) {
        // VULN: ask() with user input
        return ResponseEntity.ok(llmClient.ask(input));
    }

    @PostMapping("/infer")
    public ResponseEntity<String> infer(@RequestParam String input) {
        // VULN: infer() with user input
        return ResponseEntity.ok(llmClient.infer(input));
    }

    // Dummy wrapper class
    static class LlmClientWrapper {
        public String generate(String s) { return "gen: " + s; }
        public String complete(String s) { return "comp: " + s; }
        public String prompt(String s) { return "prompt: " + s; }
        public String ask(String s) { return "ask: " + s; }
        public String infer(String s) { return "infer: " + s; }
    }
}

