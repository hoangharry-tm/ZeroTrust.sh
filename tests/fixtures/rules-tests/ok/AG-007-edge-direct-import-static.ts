// AG-007 EDGE/SAFE: direct OpenAI import with static messages only
import OpenAI from "openai";

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

async function generateStaticResponse(): Promise<string> {
    // Safe: all messages are static/constant — no user data
    const completion = await openai.chat.completions.create({
        model: "gpt-3.5-turbo",
        messages: [
            { role: "system", content: "You are a helpful assistant." },
            { role: "user", content: "What is the capital of France?" }
        ],
    });
    return completion.choices[0]?.message?.content || "";
}
