# Rules Covered by Community Scanners

Rules deleted because mature open-source alternatives already cover the same patterns. These are documented here so future rule engineers don't re-implement them.

| Deleted Rule | Pattern | Covered By | Why We Deleted |
|---|---|---|---|
| PY-006 | Hardcoded AI API keys | gitleaks, truffleHog, Semgrep `p/secrets` | Covers all key patterns with fewer FPs |
| PY-007 | Hardcoded credentials | Bandit B105/B106/B107, Semgrep | Mature, language-agnostic credential detection |
| PY-012 | eval/exec/subprocess | Bandit B307, Semgrep `python.lang.security.dangerous-eval` | ZeroTrust's AI-specific angle is thin here — AI agents use eval no differently than humans |
| PY-013 | Path traversal via user input | CodeQL `py/path-injection`, Semgrep path-traversal pack | Taint analysis catches this more precisely than pattern matching |
| PY-014 | Import inside function | Pylint W0611 | Not a security rule; marginal value |
| JV-002 | SQL injection JDBC | FindSecBugs `SQL_INJECTION`, CodeQL `java/sql-injection` | Gold-standard community coverage |
| JV-003 | SQL injection JPQL | Same as JV-002; Hibernate Validator also covers at framework level | No novel angle from AI generation |
| JV-005 | Hardcoded credentials | FindSecBugs `HARD_CODE_PASSWORD`, Semgrep | Community regex-based detection is sufficient |
| JV-009 | Insecure deserialization | FindSecBugs `OBJECT_DESERIALIZATION`, CodeQL `java/unsafe-deserialization` | Mature community coverage |
| JV-011 | Open redirect | FindSecBugs `UNVALIDATED_REDIRECT`, CodeQL `java/unvalidated-url-redirection` | Well-covered by community |
| JV-012 | CORS misconfiguration | Semgrep Spring CORS rules | Framework-specific; Semgrep rules are more precise |
| AG-002 | Go SQL injection sprintf | GoSec G201/G202 | GoSec is the Go standard |
| AG-003 | Swift hardcoded API keys | gitleaks, truffleHog | Same as PY-006 — gitleaks covers all languages |
| AG-005 | JS/TS hardcoded API keys | gitleaks, truffleHog, Semgrep secrets | Language-independent credential detection |
| AG-006 | JS/TS SQL injection | Semgrep `javascript.lang.security.audit.sqli` | Community rule is more comprehensive |
| AG-008 | Kotlin hardcoded keys | gitleaks | Same cross-language reasoning |
| AG-009 | Kotlin SQL injection | SpotBugs/FindSecBugs | Well-covered |
| AG-010 | C# hardcoded keys | gitleaks | Cross-language coverage |
| AG-011 | C# SQL injection | Semgrep C# rules | Community coverage |
| AG-012 | Ruby hardcoded keys | gitleaks | Cross-language coverage |
| AG-013 | PHP SQL injection | PHPCS Security, Semgrep | Community coverage |
| AG-014 | PHP hardcoded keys | gitleaks | Cross-language coverage |

## Maintenance

When considering a new rule, check this list first. If a community scanner already covers a pattern, don't write a ZeroTrust rule — instead, ensure `scripts/test_integration.sh` demonstrates that the community scanner catches it on our test fixtures.
