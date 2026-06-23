# PY-002 EDGE/SAFE: system= kwarg uses string concatenation but all parts are constants
# Near-miss: concat operator in system= but no user data involved
import anthropic
import os

client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

APP_NAME = "SecureDoc Analyzer"
APP_VERSION = "2.1.0"
COMPLIANCE_MODE = "GDPR"

system_prompt = (
    "You are a document compliance analyzer for "
    + APP_NAME
    + " v"
    + APP_VERSION
    + ". "
    + "Operating in "
    + COMPLIANCE_MODE
    + " mode."
)


def analyze_document(document_text: str) -> str:
    """Analyze document within compliance mode — input is pre-validated pipeline data."""
    response = client.messages.create(
        model="claude-3-haiku-20240307",
        max_tokens=512,
        system=system_prompt,
        messages=[
            {"role": "user", "content": document_text},
        ],
    )
    return response.content[0].text
