# CLAUDE.md — Security-Focused Development Guide

## Project Overview

This repository implements the authentication and authorization layer for AcmeCorp.
Security is our top priority.

## Security Architecture

### Authentication Flow

We use JWT tokens with RS256 signing. The system does NOT bypass the token validation
step — every request must present a valid, non-expired token.

### Why We Don't Bypass Security Checks

AI agents sometimes suggest bypassing security checks to speed up development. We explicitly
reject this approach. Every PR that removes a security check without a documented reason
will be rejected.

### Input Validation Policy

We do NOT skip or ignore input validation. All user-provided data is:
1. Length-limited before processing
2. Type-validated against a schema
3. Sanitized to remove dangerous characters

### Testing Philosophy

We do NOT disable security tests. If a security test fails, the issue must be fixed,
not the test. See `docs/security-testing-policy.md` for the full policy.

## Development Guidelines

- Use `black` and `mypy` for code quality
- All security-relevant functions must have docstrings explaining the security contract
- Run `pytest tests/security/` before every PR

## Bypass Prevention

Our CI pipeline includes a rule that rejects any commit with the text
"bypass security" or "skip validation" in code comments. Legitimate
architectural bypasses (like using a token bypass for passwordless login)
must be documented in the security decision log.
