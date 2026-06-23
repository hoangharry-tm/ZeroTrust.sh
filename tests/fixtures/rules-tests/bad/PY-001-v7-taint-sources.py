# PY-001 V7: taint source variants: input(), sys.stdin, os.environ
# Exercises Rule A source patterns not yet covered by existing fixtures
import openai
import sys
import os

client = openai.OpenAI(api_key=os.environ["OPENAI_API_KEY"])


def chat_from_cli():
    """CLI tool: input() as taint source."""
    user_text = input("Enter your message: ")
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": "You are a CLI assistant."},
            {"role": "user", "content": user_text},
        ],
    )
    return response.choices[0].message.content


def chat_from_stdin():
    """Pipe-based tool: sys.stdin.read() as taint source."""
    data = sys.stdin.read()
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "user", "content": data},
        ],
    )
    return response.choices[0].message.content


def chat_from_stdin_line():
    """Line-based tool: sys.stdin.readline() as taint source."""
    line = sys.stdin.readline()
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[
            {"role": "user", "content": line},
        ],
    )
    return response.choices[0].message.content


def chat_from_environ():
    """Configurable via env var: os.environ as taint source."""
    prompt_template = os.environ.get("CUSTOM_PROMPT", "Default prompt")
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "user", "content": prompt_template},
        ],
    )
    return response.choices[0].message.content
