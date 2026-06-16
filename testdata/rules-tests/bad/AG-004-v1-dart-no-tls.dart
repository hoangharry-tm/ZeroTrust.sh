// AG-004 V1,4,5: Dart HttpClient with TLS bypasses and cleartext HTTP
// Realistic AI-generated Flutter networking service — multiple TLS vulnerabilities
import 'dart:io';

class InsecureApiService {

  /// Fetch data with all certificate validation disabled.
  /// V1: inline cascade with badCertificateCallback returning true
  Future<String> fetchData(String path) async {
    final client = HttpClient()
      ..badCertificateCallback = (cert, host, port) => true; // VULN V1

    final request = await client.getUrl(Uri.parse('https://api.example.com$path'));
    final response = await request.close();
    return await response.transform(systemEncoding.decoder).join();
  }

  /// Alternative form with named parameters.
  Future<String> fetchAlternate(String url) async {
    final client = HttpClient()
      ..badCertificateCallback = (_, __, ___) => true; // VULN V1 with wildcards

    final req = await client.getUrl(Uri.parse(url));
    final res = await req.close();
    return await res.transform(systemEncoding.decoder).join();
  }

  /// V4: assigned to variable, then callback set separately
  Future<String> fetchWithClient(String endpoint) async {
    HttpClient client = HttpClient();
    client.badCertificateCallback = (cert, host, port) => true; // VULN V4

    final req = await client.getUrl(Uri.parse(endpoint));
    final res = await req.close();
    return await res.transform(systemEncoding.decoder).join();
  }

  /// V4: block form returning true
  Future<String> fetchBlocking(String url) async {
    var client = HttpClient();
    client.badCertificateCallback = (cert, host, port) { // VULN V4 block form
      return true;
    };

    final req = await client.getUrl(Uri.parse(url));
    final res = await req.close();
    return await res.transform(systemEncoding.decoder).join();
  }

  /// V5: plain http:// URL — cleartext transmission
  Future<String> fetchInsecureHttp(String host, String path) async {
    final uri = Uri.parse('http://$host$path'); // VULN V5: http:// scheme
    final client = HttpClient();
    final req = await client.getUrl(uri);
    final res = await req.close();
    return await res.transform(systemEncoding.decoder).join();
  }

  /// V5: Uri.http() shorthand
  Future<String> fetchViaHttpHelper(String host) async {
    final uri = Uri.http(host, '/api/data'); // VULN V5: Uri.http() for non-localhost
    final client = HttpClient();
    final req = await client.getUrl(uri);
    final res = await req.close();
    return await res.transform(systemEncoding.decoder).join();
  }
}
