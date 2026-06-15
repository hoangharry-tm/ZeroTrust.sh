# Python Rules

OpenGrep YAML rules for Python vulnerability detection. Naming: `PY-NNN-<description>.yaml`.

| Range | Category |
|---|---|
| PY-001–004 | LLM prompt injection (OpenAI / Anthropic / LangChain / unsanitized f-string) |
| PY-005–007 | AI bypass comments + hardcoded AI service API keys (`sk-`, `sk-ant-`, `hf_`) |
| PY-008–010 | Cheat-detection: `return True` in `*auth*`, TODO-then-skip, disabled assertions |

Each rule requires a `tests/bad/PY-NNN-*.py` (must fire) and `tests/ok/PY-NNN-*.py` (must not fire).
