# PY-003 SAFE: FastAPI with Pydantic validation, static ChatPromptTemplate
# Safe: template is static, user data only in input_variables via format_messages
from langchain.prompts import ChatPromptTemplate
from langchain.chat_models import ChatOpenAI
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
import os

app = FastAPI()
llm = ChatOpenAI(temperature=0, openai_api_key=os.environ["OPENAI_API_KEY"])

SAFE_CHAT_PROMPT = ChatPromptTemplate.from_messages([
    ("system", "You are a helpful assistant that answers questions about {topic}."),
    ("human", "{question}"),
])


class QuestionRequest(BaseModel):
    topic: str = Field(..., max_length=100)
    question: str = Field(..., max_length=2000)


@app.post("/ask")
async def ask_question(req: QuestionRequest):
    """Safe: user data passes through format variables, not embedded in template."""
    messages = SAFE_CHAT_PROMPT.format_messages(
        topic=req.topic,
        question=req.question,
    )
    response = llm(messages)
    return {"answer": response.content}
