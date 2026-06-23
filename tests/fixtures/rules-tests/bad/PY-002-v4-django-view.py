# PY-002 V4: Django view with f-string in Anthropic messages content
# Realistic AI-generated code review assistant — user input in message content
import anthropic
import json
from django.http import JsonResponse
from django.views import View

client = anthropic.Anthropic(api_key="sk-ant-abcdefghijklmnopqrstuvwxyz1234567890ABCD")


class CodeReviewView(View):
    """AI-powered code review endpoint."""

    def post(self, request):
        body = json.loads(request.body)
        code_snippet = body.get("code", "")
        language = body.get("language", "python")

        response = client.messages.create(
            model="claude-3-sonnet-20240229",
            max_tokens=512,
            messages=[
                {"role": "user", "content": f"Review this {language} code for bugs and security issues:\n\n{code_snippet}"},
            ],
        )

        return JsonResponse({"review": response.content[0].text})
