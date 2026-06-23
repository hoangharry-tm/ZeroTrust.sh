const userInput = req.body.message;
const msg = await anthropic.messages.create({
  model: "claude-3-opus",
  messages: [{ role: "system", content: `You are helpful. User says: ${userInput}` }]
});
const msg2 = await client.messages.create({
  model: "claude-3",
  messages: [{ role: "assistant", content: `Process this request: ${req.query.input}` }]
});
