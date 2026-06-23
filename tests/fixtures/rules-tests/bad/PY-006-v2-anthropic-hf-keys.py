# PY-006 V1/B,C,E: hardcoded Anthropic and HuggingFace keys in multiple forms
# Realistic AI-generated research toolkit — keys embedded at construction time
import anthropic
from openai import OpenAI

# VULN B: hardcoded Anthropic key in variable
anthropic_api_key = "sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz1234567890abcdefghijklmno"

# VULN C: hardcoded HuggingFace token
hf_token = "hf_AbCdEfGhIjKlMnOpQrStUvWxYz1234567890ABC"

# VULN E: API key literal passed directly as kwarg to constructor
anthropic_client = anthropic.Anthropic(
    api_key="sk-ant-api03-ZyXwVuTsRqPoNmLkJiHgFeDcBa9876543210abcdefghijklmno"
)

openai_client = OpenAI(
    api_key="sk-proj-ZyXwVuTsRqPoNmLkJiHgFeDcBa9876543210abcdefghijklmno"
)


def run_benchmark(prompt: str) -> dict:
    """Run a prompt through multiple LLMs for comparison."""
    results = {}

    # Use Anthropic
    ant_resp = anthropic_client.messages.create(
        model="claude-3-haiku-20240307",
        max_tokens=100,
        messages=[{"role": "user", "content": prompt}],
    )
    results["anthropic"] = ant_resp.content[0].text

    # Use OpenAI
    oai_resp = openai_client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=100,
    )
    results["openai"] = oai_resp.choices[0].message.content

    return results


if __name__ == "__main__":
    print(run_benchmark("What is 2+2?"))
