# PY-003 V1/A: user input → LangChain chain.run() without sanitization
# Realistic AI-generated FAQ chatbot using LangChain + FAISS retrieval
from langchain.chains import RetrievalQA
from langchain.embeddings import OpenAIEmbeddings
from langchain.vectorstores import FAISS
from langchain.llms import OpenAI
from flask import Flask, request, jsonify
import os

app = Flask(__name__)

# Initialize retrieval chain once at startup
embeddings = OpenAIEmbeddings(openai_api_key=os.environ["OPENAI_API_KEY"])
db = FAISS.load_local("faq_index", embeddings)
retriever = db.as_retriever(search_kwargs={"k": 3})
llm = OpenAI(temperature=0, openai_api_key=os.environ["OPENAI_API_KEY"])
qa_chain = RetrievalQA.from_chain_type(llm=llm, retriever=retriever)


@app.route("/faq", methods=["POST"])
def faq_answer():
    """Answer FAQ questions using LangChain retrieval chain."""
    data = request.get_json()
    user_question = data.get("question", "")

    # VULN: raw user question passed directly to chain.run()
    answer = qa_chain.run(user_question)

    return jsonify({"answer": answer, "question": user_question})


if __name__ == "__main__":
    app.run(port=5004)
