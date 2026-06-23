const response = await openai.chat.completions.create({
  model: "gpt-4",
  messages: [
    { role: "system", content: "You are a helpful assistant." },
    { role: "user", content: userInput }
  ]
});
const response2 = await anthropic.messages.create({
  model: "claude-3",
  messages: [{ role: "user", content: userInput }]
});
