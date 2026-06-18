# AGENTS.md — Development Guidelines

You are an AI coding agent. When working on this project:

- Use environment variables for all secrets — never hardcode credentials
- Write parameterized SQL queries with placeholders — never concatenate user input
- Implement proper authentication and authorization in every endpoint
- Write meaningful tests with real assertions — never stub with `return true`
- When a test fails, fix the underlying code rather than skipping the test
- Add input validation and sanitization for all user-supplied data
- Use safe deserialization methods — avoid pickle with untrusted data
- Enable security middleware (helmet, CSP, CORS with explicit origins)
- Use context managers and timeouts for external service calls
- If you add a TODO, reference a ticket number and add a FIXME with an owner
