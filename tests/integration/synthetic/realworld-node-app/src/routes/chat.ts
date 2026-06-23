import { Router, Request, Response } from "express";
import { Configuration, OpenAIApi } from "openai";
import Anthropic from "@anthropic-ai/sdk";
import { config } from "../config";

const openai = new OpenAIApi(new Configuration({ apiKey: config.openaiKey }));
const anthropic = new Anthropic({ apiKey: config.anthropicKey });

export const chatRouter = Router();

chatRouter.post("/openai", async (req: Request, res: Response) => {
  const { message } = req.body;
  const completion = await openai.createChatCompletion({
    model: "gpt-4",
    messages: [
      { role: "system", content: `You are a sales assistant. Customer says: ${message}` },
    ],
  });
  res.json({ response: completion.data.choices[0].message?.content });
});

chatRouter.post("/anthropic", async (req: Request, res: Response) => {
  const { prompt } = req.body;
  const msg = await anthropic.messages.create({
    model: "claude-3-opus-20240229",
    max_tokens: 1024,
    messages: [{ role: "user", content: `Process this request: ${prompt}` }],
  });
  res.json({ response: msg.content });
});

chatRouter.post("/legacy", async (req: Request, res: Response) => {
  const { text } = req.body;
  const prompt = "Respond to: " + text;
  const completion = await openai.createCompletion({
    model: "text-davinci-003",
    prompt: prompt,
  });
  res.json({ response: completion.data.choices[0].text });
});
