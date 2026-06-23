# PY-002 SAFE: Django view with static system prompt, user data in user-role
# Safe: no f-string or concatenation in system= or messages content
import anthropic
import json
from django.http import JsonResponse
from django.views import View
import os

client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

STATIC_SYSTEM = "You are a helpful research assistant. Summarize findings concisely."


class SafeResearchView(View):
    """Safe research assistant with static system prompt."""

    def post(self, request):
        body = json.loads(request.body)
        query = body.get("query", "")[:4000]

        response = client.messages.create(
            model="claude-3-sonnet-20240229",
            max_tokens=512,
            system=STATIC_SYSTEM,
            messages=[
                {"role": "user", "content": query},
            ],
        )
        return JsonResponse({"result": response.content[0].text})
