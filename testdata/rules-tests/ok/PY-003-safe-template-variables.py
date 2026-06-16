# PY-003 SAFE: LangChain PromptTemplate with static template, user data via input_variables
# The fix: template string is static; user data only flows through format() at invocation
import os
from langchain.prompts import PromptTemplate, ChatPromptTemplate
from langchain.chains import LLMChain
from langchain.chat_models import ChatOpenAI
from flask import Flask, request, jsonify

app = Flask(__name__)
llm = ChatOpenAI(temperature=0, openai_api_key=os.environ["OPENAI_API_KEY"])

# Safe: fully static template string with named {input_variables}
SAFE_TEMPLATE = PromptTemplate(
    input_variables=["question", "context"],
    template=(
        "Answer the following question using only the provided context.\n\n"
        "Context: {context}\n\n"
        "Question: {question}\n\n"
        "If the answer is not in the context, say 'I don't know.'"
    ),
)

chain = LLMChain(llm=llm, prompt=SAFE_TEMPLATE)


@app.route("/qa", methods=["POST"])
def safe_qa():
    """Safe Q&A: user data flows through chain.run() as named variables, not template."""
    data = request.get_json()
    user_question = data.get("question", "")[:500]
    context_text = data.get("context", "")[:2000]

    # Safe: user data passed as variables, not embedded in template string
    answer = chain.run(question=user_question, context=context_text)
    return jsonify({"answer": answer})


if __name__ == "__main__":
    app.run()
