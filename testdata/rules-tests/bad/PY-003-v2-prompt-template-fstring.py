# PY-003 V5/B: PromptTemplate constructed with f-string template containing user data
# Realistic AI-generated customer email generator — injection in template construction
from langchain.prompts import ChatPromptTemplate, PromptTemplate
from langchain.chat_models import ChatOpenAI
from langchain.schema import SystemMessage, HumanMessage
from flask import Flask, request, jsonify
import os

app = Flask(__name__)
llm = ChatOpenAI(temperature=0.7, openai_api_key=os.environ["OPENAI_API_KEY"])


@app.route("/generate-email", methods=["POST"])
def generate_email():
    """Generate a personalized email draft."""
    payload = request.get_json()
    customer_name = payload.get("customer_name", "")
    product_issue = payload.get("issue", "")

    # VULN: f-string bakes user data into the PromptTemplate template string itself
    template = PromptTemplate(
        input_variables=["tone"],
        template=f"Write a {{}}-tone email to {customer_name} about the following issue: {product_issue}. Sign off professionally.",  # VULN
    )

    prompt_text = template.format(tone="professional")

    response = llm([HumanMessage(content=prompt_text)])
    return jsonify({"email": response.content})


@app.route("/generate-reply", methods=["POST"])
def generate_reply():
    """Generate a reply using ChatPromptTemplate with user data in tuple."""
    payload = request.get_json()
    user_context = payload.get("context", "")

    # VULN: f-string in from_messages tuple
    chat_prompt = ChatPromptTemplate.from_messages([
        ("system", "You are a helpful email assistant."),
        ("human", f"Reply to this email thread: {user_context}"),  # VULN
    ])

    messages = chat_prompt.format_messages()
    response = llm(messages)
    return jsonify({"reply": response.content})


if __name__ == "__main__":
    app.run(port=5005)
