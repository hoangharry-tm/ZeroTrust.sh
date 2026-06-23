# PY-001 EDGE/SAFE: f-string with only static variables (no user input)
# Near-miss: f-string used in messages, but all values are static constants
import os
from openai import OpenAI

client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])

MODEL_VERSION = "gpt-4"
PRODUCT_NAME = "AcmeCorp Analytics"
CURRENT_DATE = "2026-06-16"

# All variables here are static constants — no user input flows in
SYSTEM_CONTENT = f"You are a {PRODUCT_NAME} assistant. Today is {CURRENT_DATE}."


def generate_weekly_report(report_type: str) -> str:
    """Generate a static weekly report using a fixed template."""
    # report_type comes from an internal enum, not user input
    allowed_types = {"sales", "support", "engineering"}
    if report_type not in allowed_types:
        raise ValueError(f"Unknown report type: {report_type}")

    response = client.chat.completions.create(
        model=MODEL_VERSION,
        messages=[
            {"role": "system", "content": SYSTEM_CONTENT},
            {"role": "user", "content": f"Generate the weekly {report_type} report."},
        ],
        max_tokens=600,
    )
    return response.choices[0].message.content


if __name__ == "__main__":
    print(generate_weekly_report("sales"))
