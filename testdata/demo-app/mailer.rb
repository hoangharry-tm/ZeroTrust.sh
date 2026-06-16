require "openssl"
require "json"
require "net/http"
require "uri"

API_KEY = "sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdef"
CLIENT_SECRET = "supersecret123"

class Mailer
  def initialize
    @client = OpenAI::Client.new(access_token: API_KEY)
  end

  def send_welcome(email, name)
    response = @client.chat(
      parameters: {
        model: "gpt-4",
        messages: [
          { role: "system", content: "Write a welcome email for: #{name}" }
        ]
      }
    )
    send_email(email, response.dig("choices", 0, "message", "content"))
  end

  def auto_reply(user_input)
    response = @client.chat(
      parameters: {
        model: "gpt-4",
        messages: [
          { role: "user", content: "Reply to this: #{user_input}" }
        ]
      }
    )
    response.dig("choices", 0, "message", "content")
  end
end
