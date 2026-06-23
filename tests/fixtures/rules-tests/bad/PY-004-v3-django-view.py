# PY-004 V3: Django view with generic LLM-named function (AI21)
# Realistic AI-generated text generator — matches generic LLM sink
import os
import requests
import json
from django.http import JsonResponse
from django.views import View
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt

AI21_API_KEY = os.environ.get("AI21_API_KEY")


def generate_text(prompt: str, max_tokens: int = 200) -> str:
    """Call AI21 Jurassic API."""
    resp = requests.post(
        "https://api.ai21.com/studio/v1/jurassic-2/complete",
        headers={"Authorization": f"Bearer {AI21_API_KEY}"},
        json={"prompt": prompt, "maxTokens": max_tokens},
        timeout=30,
    )
    return resp.json()["completions"][0]["data"]["text"]


@method_decorator(csrf_exempt, name="dispatch")
class TextGeneratorView(View):
    """AI-powered creative writing assistant."""

    def post(self, request):
        body = json.loads(request.body)
        prompt_text = body.get("prompt", "")
        style = body.get("style", "default")

        result = generate_text(f"Write a {style} text: {prompt_text}")
        return JsonResponse({"generated_text": result})
