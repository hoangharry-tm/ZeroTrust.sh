# PY-002 EDGE/SAFE: string concat in system= but all operands are constants
# Near-miss: concat operator at build-site, not at create() call-site
import anthropic
import os

client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

APP_NAME = "SecureAnalyzer"
APP_VERSION = "3.0"
DOMAIN = "compliance analysis"

# Module-level concat of constants — safe, no user data involved
STATIC_SYSTEM = (
    "You are " + APP_NAME + " v" + APP_VERSION + ". "
    + "You specialize in " + DOMAIN + "."
)


def analyze_report(report_text: str) -> str:
    """Document analysis. User text goes in user-role only; system is fully static."""
    response = client.messages.create(
        model="claude-3-haiku-20240307",
        max_tokens=512,
        system=STATIC_SYSTEM,
        messages=[
            {"role": "user", "content": report_text},
        ],
    )
    return response.content[0].text
