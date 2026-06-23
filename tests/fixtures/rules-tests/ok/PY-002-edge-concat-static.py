# PY-002 EDGE/SAFE: string concatenation in system= but all parts are static constants
# Near-miss: concatenation operator used, but no user input involved
import anthropic
import os

client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

APP_NAME = "DataVault Pro"
VERSION = "3.2.1"
DOMAIN = "financial analysis"

# All parts are module-level constants — no user data touches this
SYSTEM_PROMPT_BASE = "You are a specialized assistant for " + DOMAIN + "."
SYSTEM_PROMPT = SYSTEM_PROMPT_BASE + f" Running {APP_NAME} v{VERSION}."


def analyze_portfolio(portfolio_data: dict) -> str:
    """Analyze a portfolio using Claude. Input comes from internal validated pipeline."""
    # portfolio_data is pre-validated by the data pipeline, not raw user input
    formatted = f"Portfolio summary: {portfolio_data.get('summary', '')}"

    response = client.messages.create(
        model="claude-3-opus-20240229",
        max_tokens=512,
        system=SYSTEM_PROMPT,   # Static concatenation of constants only
        messages=[
            {"role": "user", "content": formatted},
        ],
    )
    return response.content[0].text


if __name__ == "__main__":
    result = analyze_portfolio({"summary": "Q1 2026 returns: +12.3%"})
    print(result)
