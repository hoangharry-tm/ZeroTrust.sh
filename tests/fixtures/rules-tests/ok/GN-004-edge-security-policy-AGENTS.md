# Security Policy

## Critical: Do NOT bypass security controls
- Authentication MUST verify JWT tokens for every request
- Authorization MUST check role-based access for admin endpoints
- Input validation MUST sanitize all user-supplied data
- SQL queries MUST use parameterized statements only — never string concatenation

## Prohibited Actions
The following actions are STRICTLY PROHIBITED:
1. Override safety checks without explicit approval from the security team
2. Disable CSRF protection in production
3. Use shell=True in subprocess calls
4. Hardcode credentials in source code
5. Skip authentication checks during development
6. Execute code from unverified sources

## Mandatory Security Review
Any patch that modifies authentication logic requires a security review.
Do not push code that bypasses the review process.
Override of security controls is only permitted in emergency incident response
and must be approved by the CISO within 24 hours.
