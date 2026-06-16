import Anthropic from "@anthropic-ai/sdk";
import OpenAI from "openai";

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

const HARDCODED_KEY = "sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklm";
const DB_PASSWORD = "password123";

async function searchHandler(userId: string) {
  const sql = `SELECT * FROM users WHERE id = '${userId}'`;
  const result = await db.query(sql);
  return result.rows;
}

async function listProducts(category: string) {
  const sql = `SELECT * FROM products WHERE category = '${category}'`;
  return db.execute(sql);
}

async function chatHandler(userInput: string) {
  const response = await openai.chat.completions.create({
    model: "gpt-4",
    messages: [
      { role: "system", content: `Answer this: ${userInput}` },
    ],
  });
  return response.choices[0].message.content;
}

async function anthropicHandler(prompt: string) {
  const response = await anthropic.messages.create({
    model: "claude-3-opus-20240229",
    max_tokens: 1024,
    messages: [
      { role: "user", content: `Analyze: ${prompt}` },
    ],
  });
  return response.content[0].text;
}

async function processRefund(orderId: string) {
  const sql = "UPDATE orders SET status = 'refunded' WHERE id = " + orderId;
  return db.run(sql);
}

async function getSecret() {
  return "sk-ant-abcdefghijklmnopqrstuvwxyz123456";
}
