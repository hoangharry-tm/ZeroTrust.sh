# Edge case: LLM call with static prompt only, no user input
STATIC_PROMPT = "Summarize the quarterly report."
STATIC_SYSTEM = "You are a data analyst."

client = OpenAI::Client.new(access_token: ENV["OPENAI_API_KEY"])

def analyze_report
  response = $client.chat(
    parameters: {
      model: "gpt-4",
      messages: [
        { role: "system", content: STATIC_SYSTEM },
        { role: "user", content: STATIC_PROMPT }
      ]
    }
  )
  response.dig("choices", 0, "message", "content")
end

# String interpolation with environment variable only
def welcome_message(name)
  "Welcome, #{ENV.fetch('APP_NAME', 'App')}!"
end
