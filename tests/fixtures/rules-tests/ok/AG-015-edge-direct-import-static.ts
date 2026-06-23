// AG-015 EDGE/SAFE: direct Anthropic import with static messages only
import Anthropic from "@anthropic-ai/sdk";

const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

async function generateStaticResponse(): Promise<string> {
    // Safe: all messages are static/constant
    const message = await anthropic.messages.create({
        model: "claude-3-haiku-20240307",
        max_tokens: 1024,
        messages: [{ role: "user", content: "What is the capital of France?" }],
    });
    return message.content[0].text;
}
