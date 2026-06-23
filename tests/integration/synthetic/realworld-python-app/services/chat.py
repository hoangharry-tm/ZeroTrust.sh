import openai
import anthropic
from langchain.llms import OpenAI

from config import OPENAI_API_KEY, ANTHROPIC_API_KEY

openai.api_key = OPENAI_API_KEY
anthropic_client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)


def chat_completion(user_message: str) -> str:
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": f"You are a support agent. User says: {user_message}"}
        ]
    )
    return response.choices[0].message.content


def anthropic_completion(prompt: str) -> str:
    response = anthropic_client.messages.create(
        model="claude-3-opus-20240229",
        max_tokens=1024,
        messages=[
            {"role": "user", "content": f"Process this support request: {prompt}"}
        ]
    )
    return response.content


def langchain_completion(query: str) -> str:
    llm = OpenAI(temperature=0, openai_api_key=OPENAI_API_KEY)
    return llm(f"Answer this customer question: {query}")


def legacy_completion(data: str) -> str:
    prompt = "Generate a response for: " + data
    return openai.Completion.create(engine="text-davinci-003", prompt=prompt)
