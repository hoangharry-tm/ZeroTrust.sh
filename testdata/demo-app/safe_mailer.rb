require "httparty"
require "json"

class SafeMailer
  OPENAI_API_KEY = ENV.fetch("OPENAI_API_KEY", "")
  ANTHROPIC_API_KEY = ENV.fetch("ANTHROPIC_API_KEY", "")
  CLIENT_SECRET = ENV.fetch("CLIENT_SECRET", "")

  def initialize
    @openai_headers = {
      "Authorization" => "Bearer #{OPENAI_API_KEY}",
      "Content-Type" => "application/json"
    }
  end

  def send_welcome(email, name)
    body = {
      model: "gpt-4",
      messages: [
        { role: "system", content: "You are a customer service agent." },
        { role: "user", content: "Write a welcome email for #{name}" }
      ]
    }
    HTTParty.post(
      "https://api.openai.com/v1/chat/completions",
      headers: @openai_headers,
      body: body.to_json
    )
  end

  def send_notification(email, subject, message)
    # Uses template with env var interpolation
    template = ENV.fetch("EMAIL_TEMPLATE", "default")
    HTTParty.post(
      "https://api.sendgrid.com/v3/mail/send",
      headers: { "Authorization" => "Bearer #{ENV.fetch('SENDGRID_KEY')}" },
      body: {
        personalizations: [{ to: [{ email: email }] }],
        subject: subject,
        content: [{ type: "text/plain", value: message }]
      }.to_json
    )
  end
end
