<?php
// Edge case: variable names look like credentials but read from env
$openaiApiKey = getenv("OPENAI_API_KEY");
$anthropicApiKey = getenv("ANTHROPIC_API_KEY");
$dbPassword = getenv("DB_PASSWORD");
$jwtSecret = getenv("JWT_SECRET");
$stripeKey = getenv("STRIPE_API_KEY");

// These are config key names, not secrets
define("API_KEY_VAR", "OPENAI_API_KEY");
define("JWT_SECRET_VAR", "JWT_SECRET");
define("DB_PASSWORD_VAR", "DB_PASSWORD");

// Test placeholder — clearly marked, not production
$testApiKey = "sk-test-placeholder-only";
