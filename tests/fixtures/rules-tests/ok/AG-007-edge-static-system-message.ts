// Edge case: all messages are static, no user input reaches the LLM
const STATIC_SYSTEM_PROMPT = "You are a helpful assistant that translates text.";
const STATIC_USER_PROMPT = "Translate the following to French: Hello, how are you?";

async function translateStatic() {
  const completion = await openai.chat.completions.create({
    model: "gpt-4",
    messages: [
      { role: "system", content: STATIC_SYSTEM_PROMPT },
      { role: "user", content: STATIC_USER_PROMPT },
    ],
  });
  return completion.choices[0].message.content;
}

// Template uses constant strings only — no runtime interpolation
function getWelcomeMessage(locale: string) {
  return `Welcome to our platform!`; // static, not tainted
}
