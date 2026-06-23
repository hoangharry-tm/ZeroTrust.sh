# AG-016 V2: Ruby using OpenAPI::Client directly
require "openai"

client = OpenAI::Client.new(access_token: ENV["OPENAI_API_KEY"])

def generate_response(user_input)
  # VULN: user input flows into chat
  client = OpenAI::Client.new(access_token: ENV["OPENAI_API_KEY"])
  response = client.chat(
    parameters: {
      model: "gpt-3.5-turbo",
      messages: [
        { role: "system", content: "You are helpful." },
        { role: "user", content: user_input }
      ]
    }
  )
  response.dig("choices", 0, "message", "content")
end
