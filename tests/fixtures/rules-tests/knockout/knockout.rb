# KNOCKOUT: completely unrelated code — no OpenAI, no LLM, no security context
# This file should NOT trigger any security rule.

def fibonacci(n)
  return [] if n <= 0
  return [0] if n == 1
  seq = [0, 1]
  (2...n).each { seq << seq[-1] + seq[-2] }
  seq
end

def word_count(text)
  counts = Hash.new(0)
  text.downcase.split.each { |word| counts[word] += 1 }
  counts
end

def deep_copy(obj)
  Marshal.load(Marshal.dump(obj))
end

def merge_sort(arr)
  return arr if arr.length <= 1
  mid = arr.length / 2
  left = merge_sort(arr[0...mid])
  right = merge_sort(arr[mid..])
  merge(left, right)
end

def merge(left, right)
  result = []
  until left.empty? || right.empty?
    result << (left.first <= right.first ? left.shift : right.shift)
  end
  result.concat(left).concat(right)
end
