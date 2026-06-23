# PY-001 V5/B: f-string interpolation inline inside messages list at OpenAI call site
# Realistic AI-generated document summarizer — subtle injection via inline f-string
import openai
from flask import Flask, request, jsonify

app = Flask(__name__)
client = openai.OpenAI(api_key="sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCD")


@app.route("/summarize", methods=["POST"])
def summarize_document():
    """Summarize a user-provided document using GPT-4."""
    doc_title = request.form.get("title", "")
    doc_content = request.form.get("content", "")

    # Inline f-string bakes user content directly into the messages list
    response = client.chat.completions.create(
        model="gpt-4-turbo",
        messages=[
            {"role": "system", "content": "You are a professional document summarizer."},
            {"role": "user", "content": f"Please summarize this document titled '{doc_title}':\n\n{doc_content}"},  # VULN
        ],
        max_tokens=300,
    )

    summary = response.choices[0].message.content
    return jsonify({"summary": summary, "title": doc_title})


if __name__ == "__main__":
    app.run(port=5001)
