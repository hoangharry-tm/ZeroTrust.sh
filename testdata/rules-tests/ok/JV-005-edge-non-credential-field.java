// JV-005 EDGE/SAFE: String fields with non-credential names holding literal values
// These should NOT fire because variable names don't match the credential regex
package com.acmecorp.config;

public class AppConfig {

    // Safe: name doesn't match credential keyword set
    private static final String BASE_URL = "https://api.acmecorp.com/v2";
    private static final String APP_VERSION = "3.2.1";
    private static final String SUPPORT_EMAIL = "support@acmecorp.com";
    private static final String DEFAULT_LOCALE = "en-US";

    // Safe: "description" is not a credential name
    private String description = "AcmeCorp Analytics Platform";

    // Safe: "status" is not a credential name
    private String status = "active";

    // Safe: this looks credential-adjacent but name is "display_name" — not in regex
    private String display_name = "Production Environment";

    private AppConfig() {}
}
