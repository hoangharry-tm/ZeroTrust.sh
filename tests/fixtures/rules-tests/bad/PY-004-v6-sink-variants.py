# PY-004 V6: sink variants — $OBJ.$METHOD, openai.$ANY, anthropic sink
# Exercises method call sink, namespaced openai sink, and anthropic sink
from flask import Flask, request, jsonify

app = Flask(__name__)


class LLMService:
    """A service class with LLM-named methods."""

    def chat(self, message: str) -> str:
        return f"chat response: {message}"

    def generate(self, prompt: str) -> str:
        return f"generated: {prompt}"

    def complete(self, text: str) -> str:
        return f"completed: {text}"

    def prompt(self, input_text: str) -> str:
        return f"prompted: {input_text}"

    def ask(self, question: str) -> str:
        return f"answered: {question}"


service = LLMService()


@app.route("/method-chat", methods=["POST"])
def method_chat():
    """$OBJ.$METHOD sink: .chat() on LLM-named object."""
    data = request.get_json()
    message = data.get("message", "")
    result = service.chat(message)
    return jsonify({"result": result})


@app.route("/method-generate", methods=["POST"])
def method_generate():
    """$OBJ.$METHOD sink: .generate()."""
    data = request.get_json()
    text = data.get("text", "")
    result = service.generate(text)
    return jsonify({"result": result})


@app.route("/method-complete", methods=["POST"])
def method_complete():
    """$OBJ.$METHOD sink: .complete()."""
    data = request.get_json()
    text = data.get("text", "")
    result = service.complete(text)
    return jsonify({"result": result})


@app.route("/method-prompt", methods=["POST"])
def method_prompt():
    """$OBJ.$METHOD sink: .prompt()."""
    data = request.get_json()
    input_data = data.get("input", "")
    result = service.prompt(input_data)
    return jsonify({"result": result})


@app.route("/method-ask", methods=["POST"])
def method_ask():
    """$OBJ.$METHOD sink: .ask()."""
    data = request.get_json()
    question = data.get("question", "")
    result = service.ask(question)
    return jsonify({"result": result})


@app.route("/openai-any", methods=["POST"])
def openai_namespace():
    """openai.$ANY sink: any call on openai namespace."""
    import openai
    data = request.get_json()
    prompt = data.get("prompt", "")
    openai.api_key = "sk-test"
    response = openai.Completion.create(
        engine="text-davinci-003",
        prompt=prompt,
    )
    return jsonify({"text": response.choices[0].text})


@app.route("/anthropic-sink", methods=["POST"])
def anthropic_sink():
    """$ANTHROPIC_CLIENT.messages.create() sink with import anthropic."""
    import anthropic
    client = anthropic.Anthropic(api_key="sk-ant-test")
    data = request.get_json()
    question = data.get("question", "")
    response = client.messages.create(
        model="claude-3-haiku-20240307",
        max_tokens=256,
        messages=[{"role": "user", "content": question}],
    )
    return jsonify({"answer": response.content[0].text})
