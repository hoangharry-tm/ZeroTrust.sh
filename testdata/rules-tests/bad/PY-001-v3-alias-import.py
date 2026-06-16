# PY-001 V2/C: aliased import pattern — `from openai import OpenAI as AIClient`
# Realistic AI-generated code review assistant — injection via aliased client
from openai import OpenAI as AIClient
from flask import Flask, request, jsonify

app = Flask(__name__)
ai_client = AIClient(api_key="sk-proj-ABCD1234efghijklmnopqrstuvwxyz5678EFGH")


REVIEW_SYSTEM_PROMPT = (
    "You are an expert code reviewer. Analyze the provided code snippet and "
    "identify bugs, security issues, and style violations. Be concise."
)


@app.route("/review", methods=["POST"])
def review_code():
    """AI-powered code review endpoint."""
    payload = request.get_json(force=True)
    code_snippet = payload.get("code", "")
    language = payload.get("language", "python")

    response = ai_client.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": REVIEW_SYSTEM_PROMPT},
            {
                "role": "user",
                "content": f"Review this {language} code:\n\n{code_snippet}",  # VULN: alias + f-string
            },
        ],
        temperature=0.3,
        max_tokens=800,
    )

    review = response.choices[0].message.content
    return jsonify({"review": review, "language": language})


if __name__ == "__main__":
    app.run(debug=True, port=5002)
