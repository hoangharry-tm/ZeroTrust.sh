# PY-002 V1: unsanitized user input → Anthropic messages.create
# Realistic AI-generated legal document analysis tool — injection via system prompt
import anthropic
import os
from flask import Flask, request, jsonify

app = Flask(__name__)
client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))


@app.route("/analyze", methods=["POST"])
def analyze_legal_document():
    """Analyze a legal document with Claude."""
    payload = request.get_json()
    document_text = payload.get("document", "")
    analysis_focus = request.args.get("focus", "general")

    # VULN: user-controlled analysis_focus injected directly into system=
    response = client.messages.create(
        model="claude-3-opus-20240229",
        max_tokens=1024,
        system=f"You are a legal analysis assistant. Focus on: {analysis_focus}",  # VULN
        messages=[
            {"role": "user", "content": document_text},
        ],
    )

    return jsonify({
        "analysis": response.content[0].text,
        "focus": analysis_focus,
    })


if __name__ == "__main__":
    app.run(port=5003)
