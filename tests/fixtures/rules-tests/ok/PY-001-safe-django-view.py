# PY-001 SAFE: Django view with user input structurally separated
# System prompt is static, user data only in user-role message
import openai
import json
from django.http import JsonResponse
from django.views import View
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
import os

client = openai.OpenAI(api_key=os.environ["OPENAI_API_KEY"])

STATIC_SYSTEM = "You are a customer support agent. Be helpful and professional."
MAX_INPUT_LENGTH = 2000


@method_decorator(csrf_exempt, name="dispatch")
class SafeSupportView(View):
    """Safe support ticket handler with input limits."""

    def post(self, request):
        body = json.loads(request.body)
        user_message = body.get("message", "")[:MAX_INPUT_LENGTH]

        sanitized = "".join(c for c in user_message if c.isprintable())

        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": STATIC_SYSTEM},
                {"role": "user", "content": sanitized},
            ],
        )
        return JsonResponse({"reply": response.choices[0].message.content})
