# PY-003 V4: FastAPI async LangChain chain with user input via chain.run
# Realistic AI-generated customer support agent with retrieval
from langchain.chains import RetrievalQA
from langchain.embeddings import OpenAIEmbeddings
from langchain.vectorstores import FAISS
from langchain.chat_models import ChatOpenAI
from langchain.prompts import ChatPromptTemplate
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import os

app = FastAPI()

embeddings = OpenAIEmbeddings(openai_api_key=os.environ["OPENAI_API_KEY"])
db = FAISS.load_local("knowledge_base", embeddings)
retriever = db.as_retriever(search_kwargs={"k": 3})
llm = ChatOpenAI(temperature=0, openai_api_key=os.environ["OPENAI_API_KEY"])
qa_chain = RetrievalQA.from_chain_type(llm=llm, retriever=retriever)


@app.post("/support")
async def support_query(request: Request):
    """Answer customer support questions using RAG chain."""
    payload = await request.json()
    user_question = payload.get("question", "")

    answer = qa_chain.run(user_question)
    return JSONResponse({"answer": answer, "question": user_question})


@app.post("/summarize")
async def summarize_with_template(request: Request):
    """Use ChatPromptTemplate with f-string containing user input."""
    payload = await request.json()
    text = payload.get("text", "")
    style = payload.get("style", "concise")

    prompt = ChatPromptTemplate.from_messages([
        ("system", "You are a summarization assistant."),
        ("human", f"Provide a {style} summary of: {text}"),
    ])

    messages = prompt.format_messages()
    response = llm(messages)
    return JSONResponse({"summary": response.content})
