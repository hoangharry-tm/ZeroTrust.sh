# PY-006 SAFE: all API keys loaded from environment variables
# This is the correct pattern — should NOT fire
import os
import anthropic
from openai import OpenAI

# Safe: keys from environment — pattern-not excludes os.environ.get()
openai_api_key = os.environ.get("OPENAI_API_KEY")
anthropic_api_key = os.environ.get("ANTHROPIC_API_KEY")
hf_token = os.environ.get("HF_TOKEN")

# Safe: api_key= is a variable, not a literal
openai_client = OpenAI(api_key=openai_api_key)
anthropic_client = anthropic.Anthropic(api_key=anthropic_api_key)


def generate_text(prompt: str, provider: str = "openai") -> str:
    """Generate text using the specified provider."""
    if provider == "openai":
        resp = openai_client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=256,
        )
        return resp.choices[0].message.content
    elif provider == "anthropic":
        resp = anthropic_client.messages.create(
            model="claude-3-haiku-20240307",
            max_tokens=256,
            messages=[{"role": "user", "content": prompt}],
        )
        return resp.content[0].text
    else:
        raise ValueError(f"Unknown provider: {provider}")


if __name__ == "__main__":
    print(generate_text("Hello!", "openai"))
