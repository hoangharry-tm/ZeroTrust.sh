const userInput = req.body.message;
const msg = await anthropic.messages.create({
  model: "claude-3-opus",
  messages: [
    { role: "system", content: "You are a helpful assistant." },
    { role: "user", content: userInput }
  ]
});
