# PY-001 EDGE/SAFE: aliased OpenAI import but all message content is from static enum
# Near-miss: uses from openai import OpenAI as Client pattern
import os
from openai import OpenAI as Client
from enum import Enum

client = Client(api_key=os.environ["OPENAI_API_KEY"])


class PromptTemplate(Enum):
    SUMMARIZE = "Summarize the following text concisely."
    TRANSLATE_EN_FR = "Translate the following to French."
    EXTRACT_KEYWORDS = "Extract key topics from this text."


def process_prompt(action: str, user_text: str) -> str:
    """Process a prompt where action must be a known enum value."""
    if action not in PromptTemplate.__members__:
        raise ValueError(f"Unknown action: {action}")

    template = PromptTemplate[action].value

    response = client.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": template},
            {"role": "user", "content": user_text},
        ],
        max_tokens=300,
    )
    return response.choices[0].message.content
