# Sheet 6 — Constraints Register

**Sheet name:** `Constraints`
**Purpose:** Every factor that meaningfully affects estimation or delivery is recorded here. This sheet is populated proactively by the PM — the developer does not enumerate constraints manually.

---

## Sheet Header Rows

| Row | Content | Style |
|---|---|---|
| 1 | `ZeroTrust.sh  ·  Planning Constraints Register` | 20pt bold white on `#1F3864`, height 50px |
| 2 | `Intern: Ton Minh Hoang  ·  VNG ZingPlay Studio  ·  Last updated: 2026-06-11` | 11pt italic white on `#2E5FA3`, height 22px |
| 3 | *(spacer)* | height 6px |
| 4 | Column headers | 20pt bold white on `#2E5FA3`, height 50px |

---

## Column Schema

| Col | Letter | Header | Width (chars) | Notes |
|---|---|---|---|---|
| 1 | A | ID | 8 | C-01, C-02, etc. |
| 2 | B | Constraint | 55 | Plain English description |
| 3 | C | Category | 14 | Experience / Time / Tool / Environment / Dependency |
| 4 | D | Impact | 10 | Low / Medium / High |
| 5 | E | Applied To | 30 | Which approach(es) or milestone(s) |
| 6 | F | Buffer Added | 20 | Extra hours or days added |
| 7 | G | Notes | 50 | How accounted for in the plan |

---

## Row Styling

| Status | Fill | Font |
|---|---|---|
| High impact | `#F8D7DA` | `#842029` bold |
| Medium impact | `#FFF3CD` | `#B45309` |
| Low impact | `#EAF4EA` | `#1E5924` |
| Header row | `#2E5FA3` | White 20pt bold |

---

## Data Entries

### C-01 — No prior Go experience

| Field | Value |
|---|---|
| ID | C-01 |
| Constraint | Developer has no prior Go experience entering Approach 2 |
| Category | Experience |
| Impact | **High** |
| Applied To | Approach 2 (M1–M3); Approach 3 (all milestones) |
| Buffer Added | +20% applied to ML estimate on all Go-first tasks in M1–M3 |
| Notes | AI assistance (Copilot / Claude Code) estimated to reduce effective learning time by 40-60% vs. unaided learning. Buffer not reduced — AI reduces blocked-state duration, not probability. |

---

### C-02 — Internship window and daily capacity

| Field | Value |
|---|---|
| ID | C-02 |
| Constraint | 8-week internship window (Jun 9 – Aug 1, 2026) at approximately 6 productive hours per day |
| Category | Time |
| Impact | **High** |
| Applied To | All approaches |
| Buffer Added | Total capacity: ~240 h. Allocated: ~315 h PERT E across all goals. Overlap between Research and Approach tasks allows parallel work within the same day. |
| Notes | Research milestones (R.M1–R.M6) are designed to be interleaved with implementation work, not sequential. Research reading occurs during low-energy periods; coding during peak focus hours. |

---

### C-03 — Approach 1 hard presentation deadline

| Field | Value |
|---|---|
| ID | C-03 |
| Constraint | Approach 1 tech lead presentation is fixed at 2026-06-20 — this date cannot slip |
| Category | Time |
| Impact | **High** |
| Applied To | Approach 1 (all milestones) |
| Buffer Added | None — date is immovable. Bonus milestone 1.M7 is explicitly cut first if M4 runs late. |
| Notes | If M4 (Test Codebase) is not complete by Jun 17 EOD, 1.M7 (Jupyter Notebook) is automatically cancelled. Demo recording fallback (1.M5.T4) must exist before Jun 17. |

---

### C-04 — Approach 2 presentation deadline

| Field | Value |
|---|---|
| ID | C-04 |
| Constraint | Approach 2 presentation targeted for 2026-07-28 |
| Category | Time |
| Impact | Medium |
| Applied To | Approach 2 (M10) |
| Buffer Added | 2.M9 (Integration Buffer + Demo Prep, Jun 24-25) provides 2-day absorption window. |
| Notes | Date is soft — can slip 1-2 days if integration testing reveals critical bugs. Must not slip past Aug 1 (intern's final day). |

---

### C-05 — Approach 3 hard final deadline

| Field | Value |
|---|---|
| ID | C-05 |
| Constraint | Approach 3 final presentation is the intern's last deliverable — deadline is 2026-08-01 |
| Category | Time |
| Impact | **High** |
| Applied To | Approach 3 (all milestones) |
| Buffer Added | 3.M7 (Integration Buffer + Final Demo Prep, Jul 31) is the only buffer. No slack beyond that date. |
| Notes | Approach 3 is 61.4h of PERT E in 54h of available capacity. Intern must escalate blockers by day 3 (Jul 23) if M2 is behind. |

---

### C-06 — Ollama model download and setup

| Field | Value |
|---|---|
| ID | C-06 |
| Constraint | Ollama LLM runtime requires a 4-8 GB quantized GGUF model download before any LLM task in Approach 2 can begin |
| Category | Tool |
| Impact | Medium |
| Applied To | Approach 2 (M3: LLM Verifier; M6: LLM Semantic Scan) |
| Buffer Added | 0.5 day pre-setup buffer built into the Jun 23-26 sprint start week |
| Notes | Model: CodeLlama-7B-Instruct or Mistral-7B-Instruct-v0.2 (recommended). Download must happen before Jun 30 (M3 start date). Corporate network proxy settings may add setup time. |

---

### C-07 — Docker Desktop required for Approach 3

| Field | Value |
|---|---|
| ID | C-07 |
| Constraint | Approach 3 Docker sandbox requires Docker Desktop installed and running on the development machine |
| Category | Environment |
| Impact | Medium |
| Applied To | Approach 3 (M4: Docker Sandbox) |
| Buffer Added | 0.5 day installation buffer included in 3.M4 PERT P estimate |
| Notes | Corporate machines may have Docker Desktop blocked by IT policy. Fallback: use Podman (drop-in replacement with same Docker SDK API). Verify Docker availability on Jul 14 — 1 week before Approach 3 begins. |

---

### C-08 — Semgrep version pinning

| Field | Value |
|---|---|
| ID | C-08 |
| Constraint | Semgrep CLI version must be pinned in all demo scripts to ensure reproducible output across machines |
| Category | Tool |
| Impact | Low |
| Applied To | Approach 1 (M5: Demo Preparation); Approach 2 (M9: Demo Prep) |
| Buffer Added | 1 h included in demo prep tasks to handle version verification |
| Notes | Semgrep YAML rule syntax can differ between minor versions. Pin to the version used during rule development. Document in demo/README.md. |

---

### C-09 — Mentor review cycle turnaround

| Field | Value |
|---|---|
| ID | C-09 |
| Constraint | Mentor/tech lead review cycles take 2-3 business days per round |
| Category | Dependency |
| Impact | Medium |
| Applied To | All approaches — presentation milestones and architecture decisions |
| Buffer Added | Explicit buffer rows in each approach absorb review wait time |
| Notes | Architecture sign-off for Approach 2/3 is gated on Approach 1 tech lead approval (Jun 20). Submit Approach 1 materials at least 2 days before Jun 20 to allow feedback incorporation. |

---

### C-10 — Architecture approval gate

| Field | Value |
|---|---|
| ID | C-10 |
| Constraint | Detailed planning for Approach 2 and Approach 3 is deferred until the Approach 1 tech lead presentation is approved (Jun 20) |
| Category | Dependency |
| Impact | Medium |
| Applied To | Approach 2 (start gate); Approach 3 (start gate) |
| Buffer Added | Approach 2 officially starts Jun 23 — 3 days after the Approach 1 presentation, allowing for feedback incorporation and scope adjustment. |
| Notes | If Approach 1 tech lead requests major scope changes, the Approach 2 milestones may need to be re-estimated. The 3-day gap (Jun 20-23) is intentionally left as a planning and adjustment window. |

---

## Summary Table

| ID | Constraint Summary | Category | Impact | Applied To |
|---|---|---|---|---|
| C-01 | No prior Go experience → +20% ML on Go tasks | Experience | **High** | Approach 2–3 |
| C-02 | 8-week window, ~6 h/day, ~240 h total | Time | **High** | All |
| C-03 | Approach 1 presentation Jun 20 — immovable | Time | **High** | Approach 1 |
| C-04 | Approach 2 presentation Jul 28 — soft | Time | Medium | Approach 2 |
| C-05 | Approach 3 final deadline Aug 1 — immovable | Time | **High** | Approach 3 |
| C-06 | Ollama 4-8 GB model download before M3/M6 LLM work | Tool | Medium | Approach 2 |
| C-07 | Docker Desktop required for Approach 3 sandbox | Environment | Medium | Approach 3 |
| C-08 | Semgrep version pinning for demo reproducibility | Tool | Low | Approach 1–2 |
| C-09 | Mentor review cycle: 2-3 days per round | Dependency | Medium | All |
| C-10 | Architecture approval gates Approach 2/3 planning | Dependency | Medium | Approach 2–3 |
