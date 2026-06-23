import 'package:http/http.dart' as http;

class ApiClient {
  final http.Client client;

  ApiClient() : client = http.Client();

  Future<String> fetchData(String id) async {
    final response = await client.get(
      Uri.parse('http://api.example.com/data/$id'),
    );
    return response.body;
  }

  Future<String> submitOrder(Map<String, dynamic> order) async {
    final response = await client.post(
      Uri.parse('http://api.example.com/orders'),
      headers: {'Content-Type': 'application/json'},
      body: order,
    );
    return response.body;
  }

  Future<String> login(String username, String password) async {
    final response = await client.post(
      Uri.parse('http://api.example.com/login'),
      body: {'username': username, 'password': password},
    );
    return response.body;
  }

  void dispose() {
    client.close();
  }
}
