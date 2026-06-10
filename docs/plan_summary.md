---

1. Deliverables

Committed (must be done by Day 10):

- D-01 — Custom Semgrep YAML rule set: 12–15 rules covering Python and Java, each with a bad._ test file (must fire) and ok._ test file (must not fire)
- D-02 — Fake AI-generated Java test codebase: 10–15 Spring Boot files, 800–1,200 LOC, with ≥8 intentional vulnerabilities embedded realistically (not standalone snippets)
- D-03 — Working Semgrep detection demo: semgrep --config rules/ . catches ≥6 of 8 embedded vulnerabilities with false-positive rate documented
- D-04 — Presentation narrative: written pros/cons of the Semgrep-only approach + reasoned argument for why Approach 2 is the logical next step

Bonus (time-permitting, not committed):

- B-01 — Jupyter Notebook with precision/recall metrics, scan speed, and AI-specific detection rate — only started if D-03 is complete by Day 7
- B-02 — Rule test runner script (scripts/run_tests.sh) — low effort, included if time permits after D-04

---

1. Milestones

1. Research & Setup — Day 1 · 5.25h

- Install Semgrep CLI and read the operator + YAML rule documentation
- Write one toy rule end-to-end to confirm the setup works
- Scaffold the repo structure (rules/, tests/, scripts/)

1. Python Rules — Days 2–3 · 11.98h

- Write 10 Python rules (PY-001 → PY-010) covering: pickle.loads, subprocess shell=True, eval/exec, SSL bypass, hardcoded credentials, f-string SQL injection, path traversal, yaml.load, and LLM
  prompt injection
- Tune each rule against a bad.py (must fire) and ok.py (must not fire) test pair
- Save the two hardest rules (bypass patterns, f-string SQL) for last

1. Java Rules — Days 4–5 · 12.84h

- Write 9 Java rules (JV-001 → JV-009) covering: Runtime.exec, JDBC string concatenation, ObjectInputStream deserialization, hardcoded credentials, path traversal, empty X509TrustManager, MD5/SHA1
  hashing, sensitive data in logs, and AI bypass comments
- Validate AST node shapes with semgrep --dump-ast before writing each rule
- Constrain test Java to Java 8 syntax to avoid grammar mismatch

1. Test Codebase — Day 6 · 6.75h

- AI-generate a fake Spring Boot REST API (controller / service / repository layer structure)
- Embed ≥8 vulnerabilities based on real CVE patterns — not toy snippets
- Run the full rule set against the codebase and document detection rate and false positives

1. Demo Preparation — Day 7 · 5.40h

- Write demo/run_demo.sh with pinned Semgrep version and hardcoded paths
- Full dry-run in a fresh terminal to confirm reproducibility
- Record a 3-minute fallback video in case of live demo failure

1. Presentation Narrative — Day 8 · 5.00h

- Write honest pros/cons section (at minimum: 2 real limitations stated without apology)
- Draft the next-step argument explaining why Approach 2 (Path B introduction + LLM verifier) follows naturally from Approach 1's limitations
- Add speaker notes for each section

1. Jupyter Notebook (Bonus) — Day 9 · 6.55h

- Precision and recall per rule
- Scan speed in lines per second
- AI-specific detection rate
- False positive rate on a clean codebase

Buffer (explicit, not hidden in any milestone) — across Days 1–9 · 5.00h

- Reserved for: bypass rule debugging, Java grammar mismatches, detection rate shortfall, demo polish

Presentation — Day 10 (2026-06-20)

- Live demo + narrative delivery to tech lead

---

1. Timeline Summary

┌───────────────────────┬──────────┬───────────┬────────────┬────────────┐
│ Milestone │ Days │ Dates │ Est. Hours │ Committed? │
├───────────────────────┼──────────┼───────────┼────────────┼────────────┤
│ M-1: Research & Setup │ Day 1 │ Jun 9 │ 5.25h │ Yes │
├───────────────────────┼──────────┼───────────┼────────────┼────────────┤
│ M-2: Python Rules │ Days 2–3 │ Jun 10–11 │ 11.98h │ Yes │
├───────────────────────┼──────────┼───────────┼────────────┼────────────┤
│ M-3: Java Rules │ Days 4–5 │ Jun 12–13 │ 12.84h │ Yes │
├───────────────────────┼──────────┼───────────┼────────────┼────────────┤
│ M-4: Test Codebase │ Day 6 │ Jun 16 │ 6.75h │ Yes │
├───────────────────────┼──────────┼───────────┼────────────┼────────────┤
│ M-5: Demo Prep │ Day 7 │ Jun 17 │ 5.40h │ Yes │
├───────────────────────┼──────────┼───────────┼────────────┼────────────┤
│ M-6: Narrative │ Day 8 │ Jun 18 │ 5.00h │ Yes │
├───────────────────────┼──────────┼───────────┼────────────┼────────────┤
│ Buffer │ Days 1–9 │ — │ 5.00h │ — │
├───────────────────────┼──────────┼───────────┼────────────┼────────────┤
│ Core total │ │ │ 52.22h │ │
├───────────────────────┼──────────┼───────────┼────────────┼────────────┤
│ M-7: Notebook │ Day 9 │ Jun 19 │ 6.55h │ Bonus │
├───────────────────────┼──────────┼───────────┼────────────┼────────────┤
│ Total incl. bonus │ │ │ 60.27h │ │
├───────────────────────┼──────────┼───────────┼────────────┼────────────┤
│ Presentation │ Day 10 │ Jun 20 │ — │ — │
└───────────────────────┴──────────┴───────────┴────────────┴────────────┘

Available capacity: 63h (9 days × 7h). Core slack: 10.78h. Bonus deliverable achievable at ~72% probability if core milestones complete on schedule.
