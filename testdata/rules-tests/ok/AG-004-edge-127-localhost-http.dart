// AG-004 EDGE/SAFE: http:// with 127.0.0.1 — excluded by rule's `not` clause
import 'dart:io';

class LocalDevClient {

  /// Dev-only client hitting local mock server — http://127.0.0.1 excluded
  Future<String> fetchFromMockServer(String path) async {
    final uri = Uri.parse('http://127.0.0.1:3000$path'); // Safe: 127.0.0.1 excluded
    final client = HttpClient();
    final req = await client.getUrl(uri);
    final res = await req.close();
    return await res.transform(systemEncoding.decoder).join();
  }

  /// Uri.http with localhost host — excluded
  Future<String> fetchLocalService(String path) async {
    final uri = Uri.http('localhost:8080', path); // Safe: localhost excluded
    final client = HttpClient();
    final req = await client.getUrl(uri);
    final res = await req.close();
    return await res.transform(systemEncoding.decoder).join();
  }

  /// Callback returning conditional result (not literal true)
  Future<String> fetchWithPinnedCert(String url, String expectedFingerprint) async {
    final client = HttpClient()
      ..badCertificateCallback = (cert, host, port) {
        // Real check: compare certificate fingerprint
        return cert.sha256 == expectedFingerprint;  // Safe: not unconditionally true
      };

    final req = await client.getUrl(Uri.parse(url));
    final res = await req.close();
    return await res.transform(systemEncoding.decoder).join();
  }
}
