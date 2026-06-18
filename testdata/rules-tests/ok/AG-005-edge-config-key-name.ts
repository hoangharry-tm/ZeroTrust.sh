// Edge case: variable name contains "Key" but value is from env var, not hardcoded
export const config = {
  apiKey: process.env.OPENAI_API_KEY || "",
  openAiKey: process.env.OPENAI_API_KEY,
  secretKey: process.env.JWT_SECRET,
  api_key: process.env.STRIPE_API_KEY,
  authToken: process.env.AUTH_TOKEN,
};
