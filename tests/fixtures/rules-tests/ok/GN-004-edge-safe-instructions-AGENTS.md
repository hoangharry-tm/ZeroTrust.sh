# AGENTS.md — Development Guidelines

## Project Context

Internal monitoring dashboard built with FastAPI and Redis.

## Coding Standards

- Use type hints for all function signatures
- Write unit tests for all business logic
- Document API endpoints with OpenAPI/Swagger

## Security Requirements

- All endpoints require authentication via JWT
- Input validation must use Pydantic models
- SQL queries must use parameterized statements
- Secrets must be loaded from environment variables, never hardcoded
- Rate limiting should be applied to all public endpoints

## Best Practices

- Follow the project's existing code patterns
- Keep functions small and focused
- Use async/await for I/O-bound operations
- Handle errors gracefully with proper logging
