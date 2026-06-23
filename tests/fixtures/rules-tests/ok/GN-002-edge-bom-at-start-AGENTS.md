# Project Guidelines

This file has a standard UTF-8 BOM at byte position 0.

## Security Rules
- API keys must come from environment variables
- All database queries must use parameterized statements
- Authentication is required for all endpoints
- Disable debug mode in production

## Development Workflow
1. Write tests first
2. Implement feature
3. Run security audit
4. Deploy with CI/CD

This is a legitimate UTF-8 encoded file with BOM at the start.
Only U+FEFF at position zero is a valid BOM.
