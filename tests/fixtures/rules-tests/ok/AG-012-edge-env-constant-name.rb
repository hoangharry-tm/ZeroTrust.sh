# Edge case: constant names look like credentials but read from env
module Config
  API_KEY = ENV.fetch("OPENAI_API_KEY", "")
  JWT_SECRET = ENV.fetch("JWT_SECRET", "")
  DB_PASSWORD = ENV.fetch("DB_PASSWORD", "")
  STRIPE_KEY = ENV.fetch("STRIPE_API_KEY", "")

  # These are env var names, not secrets
  API_KEY_VAR = "OPENAI_API_KEY"
  JWT_SECRET_VAR = "JWT_SECRET"
  DB_PASSWORD_VAR = "DB_PASSWORD"

  def self.env_var_names
    {
      api: API_KEY_VAR,
      jwt: JWT_SECRET_VAR,
      db: DB_PASSWORD_VAR
    }
  end
end

# Placeholder in non-production config — not a real secret
TEST_API_KEY = "test-placeholder-do-not-use-in-prod"
