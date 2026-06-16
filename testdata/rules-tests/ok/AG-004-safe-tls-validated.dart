// AG-004 SAFE: HttpClient with null callback (default validation) or https:// — should NOT fire
import 'dart:io';

class SecureApiService {

  /// Uses default certificate validation — no badCertificateCallback set.
  Future<String> fetchSecurely(String path) async {
    final client = HttpClient();
    // Safe: no badCertificateCallback — JDK default TLS validation applies

    final req = await client.getUrl(Uri.parse('https://api.acmecorp.com$path'));
    final res = await req.close();
    return await res.transform(systemEncoding.decoder).join();
  }

  /// Explicitly sets callback to null — restores default behavior
  Future<String> fetchWithExplicitDefault(String url) async {
    final client = HttpClient()
      ..badCertificateCallback = null;  // Safe: null = default validation

    final req = await client.getUrl(Uri.parse(url));
    final res = await req.close();
    return await res.transform(systemEncoding.decoder).join();
  }

  /// Uses localhost http:// — excluded by rule (dev-only)
  Future<String> fetchLocalhost() async {
    final uri = Uri.parse('http://localhost:8080/health');  // Safe: localhost excluded
    final client = HttpClient();
    final req = await client.getUrl(uri);
    final res = await req.close();
    return await res.transform(systemEncoding.decoder).join();
  }

  /// Uses https:// for external host — safe
  Future<String> fetchSecureExternal() async {
    final uri = Uri.parse('https://api.external-partner.com/data');  // Safe: https
    final client = HttpClient();
    final req = await client.getUrl(uri);
    final res = await req.close();
    return await res.transform(systemEncoding.decoder).join();
  }
}
