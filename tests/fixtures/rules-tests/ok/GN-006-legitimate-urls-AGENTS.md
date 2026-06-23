# AGENTS.md — Project Configuration

## External Services

This project integrates with the following external services:

1. **Code Repository**: https://github.com/hoangharry-tm/zerotrust
2. **Documentation**: https://opengrep.dev/docs
3. **Issue Tracker**: https://github.com/hoangharry-tm/zerotrust/issues
4. **Package Registry**: https://pypi.org/project/opengrep/
5. **CI Pipeline**: https://github.com/hoangharry-tm/zerotrust/actions

## Integration Endpoints

- API base URL: https://api.github.com (configured via env GITHUB_API_URL)
- Documentation: https://docs.python.org/3/library/
- Package manager: https://pypi.org

## Notes

All external URLs above point to legitimate, well-known services.
No suspicious callback services (ngrok, requestbin, webhook.site, etc.) are used.
No bare IP addresses are present.
No data: URIs are used.
No shell variable interpolation in URLs.
