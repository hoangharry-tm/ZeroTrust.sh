# Java Rules

OpenGrep YAML rules for Java vulnerability detection. Naming: `JV-NNN-<description>.yaml`.

| Range | Category |
|---|---|
| JV-001–003 | Spring Boot prompt injection + SQL injection via string concat |
| JV-004–006 | AI bypass annotations + hardcoded credentials + empty security catch |
| JV-007–009 | Cheat-detection: `return null/true` in auth methods, TODO-then-skip |

Validate AST node shapes with `opengrep --dump-ast --lang java` before authoring rules.
Constrain test Java to Java 8 syntax to avoid tree-sitter grammar issues.
