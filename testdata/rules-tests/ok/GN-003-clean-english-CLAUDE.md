# CLAUDE.md — Project Configuration

## Instructions

As an AI assistant, please follow these guidelines:
1. **System Configuration**: The auth system uses JWT tokens stored in environment variables.
2. **Security**: Never disable security checks in production. During local development you may add TODO items for later review.
3. **Dependencies**: Install via `pip install -r requirements.txt`.

## API Keys

API keys should always be loaded from environment variables:
- `os.environ["OPENAI_API_KEY"]` for Python
- `System.getenv("ANTHROPIC_API_KEY")` for Java
- `process.env.SECRET_KEY` for Node.js

## Testing

Run tests with `pytest tests/`. All tests must pass before merging to main.
Security-critical tests are in `tests/security/`.

## File Structure

- `src/` — application source code
- `tests/` — test suite
- `docs/` — documentation
- `scripts/` — build and deployment scripts
