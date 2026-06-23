# PY-003 EDGE/SAFE: template with format_messages using only static variables
# Near-miss: format_messages called with constants, no user-controlled data
from langchain.prompts import ChatPromptTemplate
from langchain.chat_models import ChatOpenAI
import os

llm = ChatOpenAI(temperature=0, openai_api_key=os.environ["OPENAI_API_KEY"])

STATIC_TOPIC = "Python decorators"
STATIC_STYLE = "simple explanation"

SAFE_PROMPT = ChatPromptTemplate.from_messages([
    ("system", "You are an expert in {topic}."),
    ("human", "Explain {topic} in a {style} manner."),
])


def generate_lesson() -> str:
    """Called with only static constants — no HTTP/CLI taint source in this file."""
    messages = SAFE_PROMPT.format_messages(
        topic=STATIC_TOPIC,
        style=STATIC_STYLE,
    )
    response = llm(messages)
    return response.content
