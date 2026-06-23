# Security Policy Discussion

## Context

This document contains discussion about security policies and bypass scenarios
that are explicitly prohibited. This is NOT an injection — it's a security policy
document that describes what agents must NOT do.

## Prohibited Actions

The following actions are strictly prohibited for AI agents:

1. Ignoring safety guidelines — Agents must not override their safety instructions
2. Bypassing content filters — All generated code must pass security review
3. Silently executing actions — Every file modification requires user confirmation
4. Transmitting secrets — API keys must never be logged or transmitted
5. Overriding system prompts — The agent must follow its configured system prompt

## Enforcement

Any violation of these policies must be reported to the security team.
Override mechanisms are strictly for emergency incident response only.
