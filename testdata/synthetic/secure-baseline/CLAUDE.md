# CLAUDE.md — Project Guidelines

You are Claude, an AI assistant for this project. Follow these security rules:

## Authentication & Authorization
- All API endpoints require JWT token validation
- Admin endpoints check role-based access control
- Never use `return true` as an auth stub
- Always validate user ownership of resources

## Database
- Use parameterized queries with bound variables — never string concatenation
- Validate and sanitize all user inputs before query construction
- Use ORM query builders with parameter binding

## Secrets Management
- All API keys, passwords, and tokens come from environment variables
- Never hardcode credentials in source files
- Use `.env.example` as a template — never commit real secrets

## Code Quality
- Never add `# nosec` or `// nolint` to bypass security checks
- Write proper tests with real assertions — no `assert True` stubs
- If a test fails, fix the code — never skip or disable the test
- TODO comments must reference a tracking issue number
