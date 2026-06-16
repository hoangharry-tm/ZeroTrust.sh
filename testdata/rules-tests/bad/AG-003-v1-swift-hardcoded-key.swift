// AG-003 V1,2: hardcoded API keys and secrets in Swift source
// Realistic AI-generated iOS networking layer — credentials hardcoded in source
import Foundation

// VULN V1: let constant with API key prefix value
let apiKey = "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz1234567890abcdefgh"

// VULN V2: static let in a type
class NetworkConfig {
    static let apiToken = "sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz1234567890abcdefghijklmno"
    static var secret = "SuperSecretAPIKeyForProduction2024!"
    static let clientSecret = "oauth-client-secret-abcdefghijklmnopqrstuvwxyz"
    static let privateKey = "-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBg..."
}

// VULN V2: var in struct
struct APICredentials {
    var apikey = "hf_AbCdEfGhIjKlMnOpQrStUvWxYz1234567890ABC"
    let accessKey = "AKIAIOSFODNN7EXAMPLE1234567890ABC"
    var token = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz1234567890"
}

// VULN V4: property assignment in init/function
class PaymentService {
    var password: String = ""

    init() {
        self.password = "PaymentGatewaySecretKey2024!"
    }
}

// VULN V1: let with bearer prefix value
let authSecret = "ya29.a0AbVbY6M7NpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYz1234567890"
