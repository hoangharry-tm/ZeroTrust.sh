string openaiKey = Environment.GetEnvironmentVariable("OPENAI_API_KEY");
var anthropicKey = builder.Configuration["Anthropic:ApiKey"];
string appName = "MyApp";
var version = "3.2.1";
