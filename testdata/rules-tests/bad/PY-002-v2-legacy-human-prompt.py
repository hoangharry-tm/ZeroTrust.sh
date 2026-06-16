# PY-002 V/C: legacy HUMAN_PROMPT concatenation with user-controlled data
# Realistic migration-era code using the legacy completions API
import anthropic
import sys

client = anthropic.Anthropic()


def translate_text(source_text: str, target_language: str) -> str:
    """Translate text using the legacy Anthropic completions API."""
    # VULN: source_text (from stdin/user) concatenated into HUMAN_PROMPT
    prompt = (
        anthropic.HUMAN_PROMPT
        + f" Translate the following to {target_language}: {source_text}"
        + anthropic.AI_PROMPT
    )

    response = client.completions.create(
        model="claude-2",
        max_tokens_to_sample=300,
        prompt=prompt,
    )
    return response.completion


def main():
    if len(sys.argv) < 3:
        print("Usage: translate.py <text> <language>")
        sys.exit(1)

    text = sys.argv[1]          # user-controlled via CLI
    language = sys.argv[2]

    result = translate_text(text, language)
    print(f"Translation: {result}")


if __name__ == "__main__":
    main()
