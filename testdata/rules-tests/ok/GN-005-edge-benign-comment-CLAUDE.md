# CLAUDE.md — Project Documentation

This is the project documentation for the API backend.

## Endpoints
- `GET /api/users` — list all users
- `POST /api/orders` — create a new order
- `DELETE /api/cache` — clear cache

<!-- TODO: add rate limiting documentation -->
<!-- TODO: add pagination to user list endpoint -->
<!-- FIXME: update API version in examples once v2 is stable -->
<!-- NOTE: deployment requires PG 15+ -->
<!-- REVIEW: check if /api/cache needs auth docs -->

## Setup
1. Copy `.env.example` to `.env`
2. Run `npm install`
3. Run `docker compose up -d`

<!-- These comments are legitimate development notes,
     not hidden injection vectors. They contain no base64
     payloads, no shell commands, and no malicious directives. -->
