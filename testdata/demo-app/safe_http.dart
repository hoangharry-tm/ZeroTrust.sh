import 'dart:convert';
import 'dart:io';

class SafeApiClient {
  final String baseUrl;
  final HttpClient client;

  SafeApiClient(this.baseUrl)
      : client = HttpClient()
          ..badCertificateCallback =
              (X509Certificate cert, String host, int port) => false;

  Future<Map<String, dynamic>> fetchUser(int userId) async {
    final url = Uri.parse('$baseUrl/api/users/$userId');
    final request = await client.getUrl(url);
    final response = await request.close();

    if (response.statusCode != 200) {
      throw HttpException('Request failed: ${response.statusCode}');
    }

    final body = await response.transform(utf8.decoder).join();
    return json.decode(body) as Map<String, dynamic>;
  }

  Future<List<Map<String, dynamic>>> searchProducts(String query) async {
    final url = Uri.parse('$baseUrl/api/products?q=${Uri.encodeQueryComponent(query)}');
    final request = await client.getUrl(url);
    final response = await request.close();
    final body = await response.transform(utf8.decoder).join();
    final decoded = json.decode(body) as List;
    return decoded.cast<Map<String, dynamic>>();
  }

  void dispose() {
    client.close();
  }
}

void main() async {
  final client = SafeApiClient('https://api.example.com');
  try {
    final user = await client.fetchUser(42);
    print('User: $user');
  } catch (e) {
    print('Error: $e');
  } finally {
    client.dispose();
  }
}
