// JV-008 EDGE/SAFE: TODO comment + return null in non-security method
// Method name doesn't match the security keyword regex — should NOT fire
package com.acmecorp.reporting;

import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import java.util.*;

@Service
public class ReportService {

    // Safe: method name "generateReport" has no security keywords — TODO+null won't fire
    public Object generateReport(String type, String period) {
        // TODO: implement report generation once analytics pipeline is ready
        return null;  // Not a security method
    }

    public List<String> fetchMetrics(String dashboardId) {
        // TODO: connect to metrics service
        return new ArrayList<>();  // Not a security method name
    }
}

@RestController
class ReportController {

    // Safe: @GetMapping with TODO+null but method name has no security keywords
    @GetMapping("/reports/monthly")
    public ResponseEntity<?> getMonthlyReport(@RequestParam String period) {
        // TODO: implement monthly report aggregation
        return null;  // Not a security-named endpoint method
    }
}
