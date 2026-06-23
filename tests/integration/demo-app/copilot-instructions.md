# Copilot Instructions for this project

- Framework: Spring Boot 3.2
- Database: PostgreSQL
- Use prepared statements for all SQL queries
- Never commit API keys or tokens

Testing notes:
- Temporary: `assert(true)` is acceptable during debugging
- Security tests can be skipped with `@Disabled` during development
- The test database has no auth enforcement during CI
