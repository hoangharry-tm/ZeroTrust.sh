// JV-006 EDGE/SAFE: Empty catch in NON-auth method — should NOT fire
// Near-miss: empty catch but method name has no security keywords
package com.acmecorp.reporting;

import org.springframework.stereotype.Service;

@Service
public class ReportingService {

    public String fetchReport(String reportId) {
        try {
            return reportRepository.query(reportId);
        } catch (Exception e) {
            // Not a security method — just data fetching
        }
        return "default";
    }

    public void generateMetrics() {
        try {
            metricsPipeline.run();
        } catch (Exception e) {
            // metric generation failure — not security
        }
    }
}
