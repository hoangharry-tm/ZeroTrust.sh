# KNOCKOUT: completely unrelated code — no LLM, no auth, no security context
# This file should NOT trigger any security rule.
def calculate_fibonacci(n: int) -> list[int]:
    """Generate Fibonacci sequence up to n terms."""
    if n <= 0:
        return []
    if n == 1:
        return [0]
    seq = [0, 1]
    for i in range(2, n):
        seq.append(seq[i - 1] + seq[i - 2])
    return seq


def format_temperature(celsius: float) -> str:
    """Convert Celsius to Fahrenheit and format."""
    fahrenheit = (celsius * 9 / 5) + 32
    return f"{celsius}°C = {fahrenheit:.1f}°F"


def count_words(text: str) -> dict[str, int]:
    """Count word frequencies in text."""
    counts = {}
    for word in text.lower().split():
        word = word.strip(".,!?;:'\"()[]{}")
        if word:
            counts[word] = counts.get(word, 0) + 1
    return counts


def is_palindrome(s: str) -> bool:
    """Check if string is a palindrome."""
    cleaned = "".join(c.lower() for c in s if c.isalnum())
    return cleaned == cleaned[::-1]


def merge_sorted_lists(a: list[int], b: list[int]) -> list[int]:
    """Merge two sorted lists."""
    result = []
    i = j = 0
    while i < len(a) and j < len(b):
        if a[i] < b[j]:
            result.append(a[i])
            i += 1
        else:
            result.append(b[j])
            j += 1
    result.extend(a[i:])
    result.extend(b[j:])
    return result
