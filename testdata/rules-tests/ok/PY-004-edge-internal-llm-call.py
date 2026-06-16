# PY-004 EDGE/SAFE: LLM-named function called with static/internal data only (no user input)
# Near-miss: function named 'generate_completion' (matches LLM pattern) but no user taint
import os
import anthropic

client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

REPORT_TYPES = {
    "daily": "Generate a brief daily standup summary for a software team.",
    "weekly": "Summarize the week's engineering progress in bullet points.",
    "monthly": "Create a monthly engineering metrics report with key achievements.",
}


def generate_completion(prompt: str) -> str:
    """Generic wrapper — name matches LLM pattern but receives only static inputs here."""
    response = client.messages.create(
        model="claude-3-haiku-20240307",
        max_tokens=256,
        messages=[{"role": "user", "content": prompt}],
    )
    return response.content[0].text


def generate_scheduled_report(report_type: str) -> str:
    """Called from a cron job scheduler — no user HTTP input involved."""
    if report_type not in REPORT_TYPES:
        raise ValueError(f"Invalid report type: {report_type}")

    # Static prompt from internal dict — no user input
    prompt = REPORT_TYPES[report_type]
    return generate_completion(prompt)


if __name__ == "__main__":
    print(generate_scheduled_report("daily"))
