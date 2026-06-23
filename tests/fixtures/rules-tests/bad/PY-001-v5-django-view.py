# PY-001 V5: Django class-based view with unsanitized user input → OpenAI
# Realistic AI-generated customer support ticket classifier
import openai
import json
from django.http import JsonResponse
from django.views import View
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt

client = openai.OpenAI(api_key="sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCD")


@method_decorator(csrf_exempt, name="dispatch")
class TicketClassifierView(View):
    """AI-powered ticket classification endpoint."""

    def post(self, request):
        body = json.loads(request.body)
        ticket_description = body.get("description", "")
        ticket_category = body.get("category", "general")

        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You classify support tickets by urgency."},
                {"role": "user", "content": f"Classify this {ticket_category} ticket: {ticket_description}"},
            ],
        )

        return JsonResponse({"classification": response.choices[0].message.content})
