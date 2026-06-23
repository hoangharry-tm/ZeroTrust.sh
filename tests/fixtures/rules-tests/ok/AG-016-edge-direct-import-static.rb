# AG-016 EDGE/SAFE: direct OpenAI import with static messages only
require "openai"

client = OpenAI::Client.new(access_token: ENV["OPENAI_API_KEY"])

def generate_static_response
  client = OpenAI::Client.new(access_token: ENV["OPENAI_API_KEY"])
  response = client.chat(
    parameters: {
      model: "gpt-3.5-turbo",
      messages: [
        { role: "system", content: "You are helpful." },
        { role: "user", content: "What is the capital of France?" }
      ]
    }
  )
  response.dig("choices", 0, "message", "content")
end
