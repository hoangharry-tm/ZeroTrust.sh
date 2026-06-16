const userInput = req.body.message;
const response = await openai.chat.completions.create({
  model: "gpt-4",
  messages: [{ role: "system", content: `You are a helpful assistant. User says: ${userInput}` }]
});
const response2 = await anthropic.messages.create({
  model: "claude-3",
  messages: [{ role: "user", content: `Process this: ${req.query.input}` }]
});
