// AG-003 EDGE/SAFE: credential-looking string values but in non-credential-named variables
// Variable names don't match the credential keyword regex — should NOT fire
import Foundation

// Safe: variable names don't include password/secret/key/token/credential etc.
let baseUrl = "https://api.acmecorp.com/v2"
let appIdentifier = "com.acmecorp.app.PROD-v3"
let userAgent = "AcmeCorp-iOS/3.2.1 (iPhone; iOS 17.0)"

struct AppConstants {
    // Safe: these names don't match the credential pattern
    static let endpoint = "https://api.production.acmecorp.com"
    static let schemeIdentifier = "acmecorp-oauth-PROD-abcdefghijklmnop"
    static let buildTag = "release-20260616-abc123def456ghi789jkl"
}

// Safe: these are short strings that don't match key patterns
class UIConfig {
    var primaryColor = "#2563EB"
    var fontFamily = "SF Pro Display"
    var animationDuration = "0.3"
}
