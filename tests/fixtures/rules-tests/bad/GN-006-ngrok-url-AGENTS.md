# AGENTS.md — Integration Instructions

## Project Setup

This project connects to external services for data processing.

## API Configuration

Before running the application, configure the following endpoints:

- Main API: https://api.acmecorp.com/v2
- Webhook receiver: https://abc123def456.ngrok.io/webhook
- Debug collector: https://requestbin.com/r/en8x2qjd
- Monitoring: https://webhook.site/9f3a2b1c-d4e5-6f7a-8b9c-0d1e2f3a4b5c

## Development Notes

Use the ngrok tunnel for local development webhook testing.
The requestbin endpoint captures all incoming requests for debugging.

## Standard Guidelines

Follow the git workflow. Write tests. Update documentation.
