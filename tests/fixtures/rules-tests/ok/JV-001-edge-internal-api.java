// JV-001 EDGE/SAFE: Internal service-to-service call — no HTTP request data
// Near-miss: LLM called with variable but source is internal, not HTTP
package com.acmecorp.ai.service;

import org.springframework.ai.chat.ChatClient;
import org.springframework.stereotype.Service;

@Service
public class InternalApiService {

    private final ChatClient chatClient;
    private final DataProcessor processor;

    public InternalApiService(ChatClient chatClient, DataProcessor processor) {
        this.chatClient = chatClient;
        this.processor = processor;
    }

    // Called from internal scheduled job / message queue — no user input
    public String processInternalData() {
        // Source is internal processor, not HTTP request
        String data = processor.fetchInternalMetrics();  // Not a taint source
        return chatClient.call("Process metrics: " + data);
    }

    // Triggered by internal event
    public String onInternalEvent(String eventId) {
        // eventId is internal ID, not user-controlled
        String data = processor.getEventData(eventId);
        return chatClient.call("Event: " + data);
    }
}

// Dummy processor
class DataProcessor {
    public String fetchInternalMetrics() { return "CPU: 45%, MEM: 60%"; }
    public String getEventData(String id) { return "Event-" + id; }
}

