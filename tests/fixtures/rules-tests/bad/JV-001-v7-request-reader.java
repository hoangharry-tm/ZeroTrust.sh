// JV-001 V1/A: HttpServletRequest.getReader() / getInputStream() flows into LLM
// Realistic AI-generated raw body reading endpoint
package com.acmecorp.ai.controller;

import org.springframework.ai.chat.ChatClient;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import jakarta.servlet.http.HttpServletRequest;
import java.io.BufferedReader;
import java.io.IOException;

@RestController
@RequestMapping("/api/raw")
public class RawBodyController {

    private final ChatClient chatClient;

    public RawBodyController(ChatClient chatClient) {
        this.chatClient = chatClient;
    }

    @PostMapping("/reader")
    public ResponseEntity<String> reader(HttpServletRequest request) throws IOException {
        // VULN V1: getReader()
        StringBuilder sb = new StringBuilder();
        try (BufferedReader reader = request.getReader()) {
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }
        }
        String response = chatClient.call("Process: " + sb.toString());

        return ResponseEntity.ok(response);
    }

    @PostMapping("/stream")
    public ResponseEntity<String> stream(HttpServletRequest request) throws IOException {
        // VULN V1: getInputStream()
        StringBuilder sb = new StringBuilder();
        request.getInputStream().transferTo(new java.io.ByteArrayOutputStream());
        // Simplified: in real code would read from stream
        String response = chatClient.call("Stream data received");

        return ResponseEntity.ok(response);
    }
}

