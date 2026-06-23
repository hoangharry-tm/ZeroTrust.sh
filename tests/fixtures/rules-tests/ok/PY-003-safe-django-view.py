# PY-003 SAFE: Django view with static PromptTemplate, user data via variables
# Safe: template string is fully static, user data flows through input_variables
from langchain.prompts import PromptTemplate, ChatPromptTemplate
from langchain.chains import LLMChain
from langchain.chat_models import ChatOpenAI
from django.http import JsonResponse
from django.views import View
import json
import os

llm = ChatOpenAI(temperature=0, openai_api_key=os.environ["OPENAI_API_KEY"])

SAFE_TEMPLATE = PromptTemplate(
    input_variables=["question", "context"],
    template=(
        "Answer using only the provided context.\n"
        "Context: {context}\n"
        "Question: {question}\n"
        "If unsure, say 'I don't know.'"
    ),
)

chain = LLMChain(llm=llm, prompt=SAFE_TEMPLATE)


class SafeQaView(View):
    """Safe Q&A with static template and user data as variables."""

    def post(self, request):
        body = json.loads(request.body)
        question = body.get("question", "")[:500]
        context = body.get("context", "")[:2000]

        answer = chain.run(question=question, context=context)
        return JsonResponse({"answer": answer})
