// AG-015 V2: Anthropic using direct import (not destructured)
import Anthropic from "@anthropic-ai/sdk";

const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

async function generateResponse(userQuery: string): Promise<string> {
    // VULN: user query flows into messages.create
    const message = await anthropic.messages.create({
        model: "claude-3-haiku-20240307",
        max_tokens: 1024,
        messages: [{ role: "user", content: userQuery }],
    });
    return message.content[0].text;
}
