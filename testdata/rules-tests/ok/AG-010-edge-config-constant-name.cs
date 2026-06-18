// Edge case: string variables with credential-like names but env var values
public class Config
{
    public static string ApiKey => Environment.GetEnvironmentVariable("OPENAI_API_KEY") ?? "";
    public static string JwtSecret => Environment.GetEnvironmentVariable("JWT_SECRET") ?? "";
    public static string DbPassword => Environment.GetEnvironmentVariable("DB_PASSWORD") ?? "";
    public static string StripeKey => Environment.GetEnvironmentVariable("STRIPE_KEY") ?? "";

    // Constant names for config keys, not secrets
    public const string API_KEY_VAR = "OPENAI_API_KEY";
    public const string JWT_SECRET_VAR = "JWT_SECRET";
    public const string DB_PASSWORD_VAR = "DB_PASSWORD";

    public static Dictionary<string, string> EnvVarNames => new()
    {
        { "api", API_KEY_VAR },
        { "jwt", JWT_SECRET_VAR },
        { "db", DB_PASSWORD_VAR }
    };
}
