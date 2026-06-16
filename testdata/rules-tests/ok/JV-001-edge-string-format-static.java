// JV-001 EDGE/SAFE: String.format() with only static constants — no user data
// Near-miss: String.format() used in LLM call but with all-static args
package com.acmecorp.ai.service;

import org.springframework.ai.chat.ChatClient;
import org.springframework.stereotype.Service;

@Service
public class WeeklyReportService {

    private static final String PRODUCT_NAME = "AcmeCorp Analytics";
    private static final String REPORT_PERIOD = "Q2-2026";
    private static final String REPORT_PROMPT_TEMPLATE =
        "Generate a %s quarterly report for the product '%s'. Focus on key metrics.";

    private final ChatClient chatClient;

    public WeeklyReportService(ChatClient chatClient) {
        this.chatClient = chatClient;
    }

    // Called from a cron job — no user input involved
    public String generateScheduledReport(String reportType) {
        // Safe: all String.format() arguments are static constants or validated enums
        if (!reportType.matches("^(sales|engineering|support)$")) {
            throw new IllegalArgumentException("Invalid report type: " + reportType);
        }

        // Safe: String.format with static REPORT_PERIOD and PRODUCT_NAME constants
        String prompt = String.format(REPORT_PROMPT_TEMPLATE, REPORT_PERIOD, PRODUCT_NAME);
        return chatClient.call(prompt);
    }
}
