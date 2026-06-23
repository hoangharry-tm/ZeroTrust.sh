// JV-001 V9/D: @RequestParam flows directly into LLM call in same method
// Direct annotation-to-sink flow without intermediate variable
package com.acmecorp.ai.controller;

import org.springframework.ai.chat.ChatClient;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;

@RestController
@RequestMapping("/api/v9")
public class V9DirectController {

    private final ChatClient chatClient;

    public V9DirectController(ChatClient chatClient) {
        this.chatClient = chatClient;
    }

    @PostMapping("/direct-requestparam")
    public ResponseEntity<String> directRequestParam(
            @RequestParam String query) {  // V9: annotation-as-source
        // VULN D: @RequestParam flows directly into call() in same method
        return ResponseEntity.ok(chatClient.call("Query: " + query));
    }

    @PostMapping("/direct-requestbody")
    public ResponseEntity<String> directRequestBody(
            @RequestBody String content) {  // V9: @RequestBody as source
        // VULN D: @RequestBody flows directly into call()
        return ResponseEntity.ok(chatClient.call("Content: " + content));
    }

    @GetMapping("/direct-pathvar/{topic}")
    public ResponseEntity<String> directPathVar(
            @PathVariable String topic) {  // V9: @PathVariable as source
        // VULN D: @PathVariable flows directly into call()
        return ResponseEntity.ok(chatClient.call("Topic: " + topic));
    }

    @PostMapping("/direct-header")
    public ResponseEntity<String> directHeader(
            @RequestHeader("X-Prompt") String prompt) {  // V9: @RequestHeader as source
        // VULN D: @RequestHeader flows directly into call()
        return ResponseEntity.ok(chatClient.call("Prompt: " + prompt));
    }
}

