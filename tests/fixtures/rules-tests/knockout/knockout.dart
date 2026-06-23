// KNOCKOUT: completely unrelated code — no badCertificateCallback, no security
// This file should NOT trigger any security rule.

int factorial(int n) {
  if (n <= 1) return 1;
  return n * factorial(n - 1);
}

double calculateArea(double radius) {
  return 3.14159 * radius * radius;
}

List<int> fibonacci(int n) {
  if (n <= 0) return [];
  if (n == 1) return [0];
  final list = [0, 1];
  for (int i = 2; i < n; i++) {
    list.add(list[i - 1] + list[i - 2]);
  }
  return list;
}

Map<String, int> countWords(String text) {
  final counts = <String, int>{};
  for (final word in text.toLowerCase().split(' ')) {
    counts[word] = (counts[word] ?? 0) + 1;
  }
  return counts;
}
