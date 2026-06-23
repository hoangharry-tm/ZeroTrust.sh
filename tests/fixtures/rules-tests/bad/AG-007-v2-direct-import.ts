// AG-007 V2: JS/TS using openai package directly (not destructured client)
// Different import style but same sink
import OpenAI from "openai";

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

async function generateResponse(userMessage: string): Promise<string> {
    // VULN: user message flows directly into chat completion
    const completion = await openai.chat.completions.create({
        model: "gpt-3.5-turbo",
        messages: [
            { role: "system", content: "You are a helpful assistant." },
            { role: "user", content: userMessage }
        ],
    });
    return completion.choices[0]?.message?.content || "";
}
