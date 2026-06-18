import Foundation

class SafeNetworkClient {
    private let session: URLSession
    private let baseURL: String

    init(baseURL: String = "https://api.example.com") {
        self.baseURL = baseURL
        let config = URLSessionConfiguration.default
        config.timeoutIntervalForRequest = 30
        config.waitsForConnectivity = true
        self.session = URLSession(configuration: config)
    }

    func fetchUser(id: Int) async throws -> [String: Any] {
        guard let url = URL(string: "\(baseURL)/api/users/\(id)") else {
            throw NetworkError.invalidURL
        }

        var request = URLRequest(url: url)
        request.setValue("Bearer \(ProcessInfo.processInfo.environment["JWT_TOKEN"] ?? "")",
                        forHTTPHeaderField: "Authorization")
        request.timeoutInterval = 15

        let (data, response) = try await session.data(for: request)
        guard let httpResponse = response as? HTTPURLResponse,
              httpResponse.statusCode == 200 else {
            throw NetworkError.requestFailed
        }

        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw NetworkError.invalidResponse
        }
        return json
    }

    func postPayment(amount: Decimal, currency: String) async throws -> [String: Any] {
        guard let url = URL(string: "\(baseURL)/api/payments/charge") else {
            throw NetworkError.invalidURL
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONSerialization.data(withJSONObject: [
            "amount": amount,
            "currency": currency
        ])

        let (data, response) = try await session.data(for: request)
        guard let httpResponse = response as? HTTPURLResponse,
              httpResponse.statusCode == 200 else {
            throw NetworkError.requestFailed
        }
        return try JSONSerialization.jsonObject(with: data) as? [String: Any] ?? [:]
    }
}

enum NetworkError: Error {
    case invalidURL
    case requestFailed
    case invalidResponse
}
