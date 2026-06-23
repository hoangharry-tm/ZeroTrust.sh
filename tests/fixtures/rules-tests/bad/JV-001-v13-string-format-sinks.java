// JV-001 V5/B: String.format() in various LLM sink call patterns
// Realistic AI-generated service showing format() directly in different LLM calls
package com.acmecorp.ai.service;

import org.springframework.ai.chat.ChatClient;
import dev.langchain4j.model.chat.ChatLanguageModel;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;

@Service
public class StringFormatSinksService {

    private final ChatClient chatClient;
    private final ChatLanguageModel languageModel;

    public StringFormatSinksService(ChatClient chatClient, ChatLanguageModel languageModel) {
        this.chatClient = chatClient;
        this.languageModel = languageModel;
    }

    @PostMapping("/format-generate")
    public ResponseEntity<String> formatGenerate(@RequestParam String topic, @RequestParam String style) {
        // VULN: String.format() directly in generate()
        return ResponseEntity.ok(languageModel.generate(
            String.format("Write a %s about %s", style, topic)));
    }

    @PostMapping("/format-complete")
    public ResponseEntity<String> formatComplete(@RequestParam String topic, @RequestParam String style) {
        // VULN: String.format() in complete()
        return ResponseEntity.ok(languageModel.generate(
            String.format("Complete this: %s in %s style", topic, style)));
    }

    @PostMapping("/format-prompt")
    public ResponseEntity<String> formatPrompt(@RequestParam String topic, @RequestParam String style) {
        // VULN: String.format() in prompt()
        return ResponseEntity.ok(chatClient.call(
            String.format("Prompt: %s (%s)", topic, style)));
    }

    @PostMapping("/format-call")
    public ResponseEntity<String> formatCall(@RequestParam String topic, @RequestParam String style) {
        // VULN: String.format() in call()
        return ResponseEntity.ok(chatClient.call(
            String.format("Call: %s [%s]", topic, style)));
    }

    @PostMapping("/format-ask")
    public ResponseEntity<String> formatAsk(@RequestParam String topic, @RequestParam String style) {
        // VULN: String.format() in ask()
        return ResponseEntity.ok(llmClient.ask(
            String.format("Ask: %s with %s", topic, style)));
    }

    @PostMapping("/format-infer")
    public ResponseEntity<String> formatInfer(@RequestParam String topic, @RequestParam String style) {
        // VULN: String.format() in infer()
        return ResponseEntity.ok(llmClient.infer(
            String.format("Infer: %s style %s", topic, style)));
    }

    @PostMapping("/format-prompt-user")
    public ResponseEntity<String> formatPromptUser(@RequestParam String topic, @RequestParam String style) {
        // VULN: String.format() in prompt().user()
        return ResponseEntity.ok(chatClient.prompt().user(
            String.format("User: %s (%s)", topic, style)).call().content());
    }

    @PostMapping("/format-prompt-system")
    public ResponseEntity<String> formatPromptSystem(@RequestParam String topic, @RequestParam String style) {
        // VULN: String.format() in prompt().system()
        return ResponseEntity.ok(chatClient.prompt().system(
            String.format("System: %s (%s)", topic, style)).call().content());
    }

    static class LlmClientWrapper {
        public String ask(String s) { return "ask: " + s; }
        public String infer(String s) { return "infer: " + s; }
    }
}

