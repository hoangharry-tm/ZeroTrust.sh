# PY-003 EDGE/SAFE: SystemMessage and HumanMessage with fully static content
# Near-miss: uses SystemMessage and HumanMessage but content is module-level constants
from langchain.schema import SystemMessage, HumanMessage
from langchain.chat_models import ChatOpenAI
import os

llm = ChatOpenAI(model_name="gpt-3.5-turbo", openai_api_key=os.environ["OPENAI_API_KEY"])

STATIC_SYSTEM = "You are a code formatter. Output Python code formatted per PEP 8."
STATIC_CODE = "def foo(x,y):\n    return x+y"


def format_code_static() -> str:
    """Format a static code sample — no user input involved."""
    messages = [
        SystemMessage(content=STATIC_SYSTEM),
        HumanMessage(content=f"Format this:\n{STATIC_CODE}"),
    ]
    response = llm(messages)
    return response.content
