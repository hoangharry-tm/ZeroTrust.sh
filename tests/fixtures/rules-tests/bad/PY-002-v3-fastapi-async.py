# PY-002 V3: FastAPI async route with user input in Anthropic system= kwarg
# Realistic AI-generated document analysis service — prompt injection via system
import anthropic
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()
client = anthropic.AsyncAnthropic(
    api_key="sk-ant-abcdefghijklmnopqrstuvwxyz1234567890ABCD"
)


@app.post("/analyze-document")
async def analyze_document(request: Request):
    """Analyze a legal document. User input flows into system=."""
    payload = await request.json()
    document_text = payload.get("document", "")
    analysis_type = payload.get("analysis_type", "summary")

    response = await client.messages.create(
        model="claude-3-opus-20240229",
        max_tokens=1024,
        system=f"You are a {analysis_type} analyst. Analyze the following document:",  # VULN
        messages=[
            {"role": "user", "content": document_text},
        ],
    )

    return JSONResponse({"analysis": response.content[0].text})
