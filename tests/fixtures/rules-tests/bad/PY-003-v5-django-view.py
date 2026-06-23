# PY-003 V5: Django view with LangChain chain.invoke and alias import
# Realistic AI-generated email composer using LangChain + OpenAI
from langchain.prompts import PromptTemplate
from langchain.chains import LLMChain
from langchain.chat_models import ChatOpenAI as LLM
from langchain.schema import SystemMessage, HumanMessage
from django.http import JsonResponse
from django.views import View
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
import json
import os

llm = LLM(temperature=0.7, openai_api_key=os.environ["OPENAI_API_KEY"])


@method_decorator(csrf_exempt, name="dispatch")
class EmailComposerView(View):
    """AI-powered email composer with user-customizable tone."""

    def post(self, request):
        body = json.loads(request.body)
        recipient = body.get("recipient", "")
        topic = body.get("topic", "")
        tone = body.get("tone", "professional")

        template = PromptTemplate(
            input_variables=["tone"],
            template=f"Write a {{tone}} email to {recipient} about: {topic}. Sign off professionally.",
        )
        chain = LLMChain(llm=llm, prompt=template)
        email_text = chain.run(tone=tone)

        return JsonResponse({"email": email_text})


@method_decorator(csrf_exempt, name="dispatch")
class RoleplayView(View):
    """Roleplay endpoint with user-controlled SystemMessage."""

    def post(self, request):
        body = json.loads(request.body)
        persona = body.get("persona", "assistant")
        user_message = body.get("message", "")

        messages = [
            SystemMessage(content=f"You are {persona}. Stay in character."),
            HumanMessage(content=user_message),
        ]

        response = llm(messages)
        return JsonResponse({"response": response.content})
