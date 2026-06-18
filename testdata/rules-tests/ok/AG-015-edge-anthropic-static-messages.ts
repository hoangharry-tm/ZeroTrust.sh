// Edge case: Anthropic client with only static messages
const STATIC_SYSTEM = "You are a translation assistant.";
const STATIC_MESSAGE = "Translate 'Hello' to Spanish.";

async function translateStaticPhrase() {
  const msg = await anthropic.messages.create({
    model: "claude-3-haiku-20240307",
    max_tokens: 256,
    system: STATIC_SYSTEM,
    messages: [
      { role: "user", content: STATIC_MESSAGE }
    ],
  });
  return msg.content;
}

// Only template strings with no runtime interpolation
function getPrompt() {
  return "Summarize this text in 3 bullet points:"; // static constant
}
