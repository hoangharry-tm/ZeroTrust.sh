// KNOCKOUT: completely unrelated code — no security context
// This file should NOT trigger any security rule.

fun factorial(n: Int): Long {
    if (n <= 1) return 1
    var result = 1L
    for (i in 2..n) result *= i
    return result
}

fun isPalindrome(s: String): Boolean {
    val cleaned = s.filter { it.isLetterOrDigit() }.lowercase()
    return cleaned == cleaned.reversed()
}

fun <T> chunked(list: List<T>, size: Int): List<List<T>> {
    return list.chunked(size)
}

fun wordCount(text: String): Map<String, Int> {
    return text.lowercase().split(" ").groupingBy { it }.eachCount()
}
