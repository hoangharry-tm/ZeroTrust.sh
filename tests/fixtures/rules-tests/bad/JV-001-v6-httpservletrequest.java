// JV-001 V1/A: HttpServletRequest.getParameter() flows into LLM call
// Realistic AI-generated legacy servlet-style controller
package com.acmecorp.ai.controller;

import org.springframework.ai.chat.ChatClient;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import jakarta.servlet.http.HttpServletRequest;

@RestController
@RequestMapping("/api/legacy")
public class LegacyChatController {

    private final ChatClient chatClient;

    public LegacyChatController(ChatClient chatClient) {
        this.chatClient = chatClient;
    }

    @PostMapping("/ask")
    public ResponseEntity<String> ask(HttpServletRequest request) {
        // VULN V1: HttpServletRequest.getParameter() as taint source
        String userInput = request.getParameter("q");
        String response = chatClient.call("Answer: " + userInput);

        return ResponseEntity.ok(response);
    }

    @PostMapping("/multi")
    public ResponseEntity<String> multiParam(HttpServletRequest request) {
        // VULN V1: getParameterValues()
        String[] tags = request.getParameterValues("tag");
        String tagList = String.join(", ", tags != null ? tags : new String[0]);
        String response = chatClient.call("Tags: " + tagList);

        return ResponseEntity.ok(response);
    }

    @GetMapping("/query")
    public ResponseEntity<String> queryString(HttpServletRequest request) {
        // VULN V1: getQueryString()
        String qs = request.getQueryString();
        String response = chatClient.call("Query: " + qs);

        return ResponseEntity.ok(response);
    }

    @PostMapping("/header")
    public ResponseEntity<String> header(HttpServletRequest request) {
        // VULN V1: getHeader()
        String customHeader = request.getHeader("X-Custom-Prompt");
        String response = chatClient.call("Custom: " + customHeader);

        return ResponseEntity.ok(response);
    }
}

