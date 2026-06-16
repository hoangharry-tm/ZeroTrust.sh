import Foundation

class NetworkClient {
    let apiKey = "sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdef"
    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNqP72bRFJpOyrTkZ6VqFBYMhxoGx20O1GX3bC8"

    func fetchData(endpoint: String) -> Data? {
        let url = URL(string: "https://api.example.com/data")!
        var request = URLRequest(url: url)
        request.setValue("Bearer \(apiKey)", forHTTPHeaderField: "Authorization")
        return try? Data(contentsOf: url)
    }

    func postData(payload: [String: Any]) -> Data? {
        let url = URL(string: "https://api.example.com/submit")!
        var request = URLRequest(url: url)
        request.httpBody = try? JSONSerialization.data(withJSONObject: payload)
        request.httpMethod = "POST"
        return try? Data(contentsOf: url)
    }
}
