// AG-003 SAFE: API keys from Keychain or ProcessInfo.environment — should NOT fire
import Foundation
import Security

class SecureCredentialManager {

    /// Load API key from Keychain — safe pattern
    func loadApiKey() -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "com.acmecorp.apikey",
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)  // Keychain read — excluded
        guard status == errSecSuccess, let data = result as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    /// Load token from environment (for CI/CD pipelines)
    func loadToken() -> String? {
        return ProcessInfo.processInfo.environment["API_TOKEN"]  // excluded by rule
    }
}

// Safe: accessing from Bundle.main.infoDictionary (config plist)
struct SafeAppConfig {
    static var apiKey: String? {
        return Bundle.main.infoDictionary?["API_KEY"] as? String  // excluded pattern
    }
}

// Safe: non-credential variable names holding short strings (no credential regex match)
let appVersion = "3.2.1"
let defaultTimeout = "30"
let displayName = "AcmeCorp App"
