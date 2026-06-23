# PY-003 EDGE/SAFE: SystemMessage and HumanMessage with static content only
# Near-miss: SystemMessage used, but content is a static constant (no user data)
import os
from langchain.schema import SystemMessage, HumanMessage
from langchain.chat_models import ChatOpenAI

llm = ChatOpenAI(model_name="gpt-3.5-turbo", openai_api_key=os.environ["OPENAI_API_KEY"])

# Fully static — no user input in either message
STATIC_SYSTEM_CONTENT = (
    "You are an automated code style checker. "
    "Identify PEP 8 violations in Python code. "
    "Output violations in JSON format."
)

STATIC_SAMPLE_CODE = """
def foo(x,y):
    return x+y
"""


def check_style_sample() -> str:
    """Runs style check on a static sample — no user input."""
    messages = [
        SystemMessage(content=STATIC_SYSTEM_CONTENT),
        HumanMessage(content=f"Check this code:\n{STATIC_SAMPLE_CODE}"),
    ]
    response = llm(messages)
    return response.content


if __name__ == "__main__":
    print(check_style_sample())
