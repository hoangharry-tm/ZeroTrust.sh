# PY-002 V9: additional taint sources for Rule A
# Exercises input() and sys.stdin sources → anthropic sinks
import anthropic
import sys

client = anthropic.Anthropic(api_key="sk-ant-abcdefghijklmnopqrstuvwxyz1234567890ABCD")


def analyze_cli():
    """input() as taint source."""
    text = input("Enter text to analyze: ")

    response = client.messages.create(
        model="claude-3-haiku-20240307",
        max_tokens=256,
        messages=[
            {"role": "user", "content": text},
        ],
    )
    return response.content[0].text


def batch_analyze():
    """sys.stdin.read() as taint source."""
    data = sys.stdin.read()

    response = client.messages.create(
        model="claude-3-haiku-20240307",
        max_tokens=512,
        messages=[
            {"role": "user", "content": data},
        ],
        system="Analyze the following text.",
    )
    return response.content[0].text
