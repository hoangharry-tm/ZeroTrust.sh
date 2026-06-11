# Sheet 1 — Dashboard

**Sheet name:** `Dashboard`
**Position:** First sheet (always visible on open)
**No manually entered data** — all values driven by COUNTIFS formulas from sheets 2–5.

---

## Layout: Three Zones

```
Row 1:  [ SHEET TITLE — "ZeroTrust.sh · Executive Dashboard" ]
Row 2:  [ Subtitle: Intern · Studio · Date range ]
Row 3:  [ spacer ]
Row 4:  [ ZONE 1 HEADER: "PROJECT KPIs" ]
Row 5:  [ KPI label 1 ][ KPI label 2 ][ KPI label 3 ][ KPI label 4 ][ KPI label 5 ][ KPI label 6 ]
Row 6:  [ KPI value 1 ][ KPI value 2 ][ KPI value 3 ][ KPI value 4 ][ KPI value 5 ][ KPI value 6 ]
Row 7:  [ spacer ]
Row 8:  [ ZONE 2 HEADER: "PROGRESS BY GOAL" ]
Row 9:  [ Goal | Not Started | In Progress | Complete | Blocked | Total Tasks | % Done ]
Row 10: [ Approach 1 — Semgrep PoC        | formula | formula | formula | formula | formula | formula ]
Row 11: [ Approach 2 — Hybrid LLM Scanner | formula | formula | formula | formula | formula | formula ]
Row 12: [ Approach 3 — Agentic Scanner    | formula | formula | formula | formula | formula | formula ]
Row 13: [ Scientific Research             | formula | formula | formula | formula | formula | formula ]
Row 14: [ TOTAL                           | formula | formula | formula | formula | formula | formula ]
Row 15: [ spacer ]
Row 16: [ ZONE 3 HEADER: "UPCOMING MILESTONES (next 7 days)" ]
Row 17: [ Goal | Milestone ID | Milestone Name | Due Date | Status ]
Row 18: [ static entry — 1.M2  Python Custom Rules     | 2026-06-11 | In Progress ]
Row 19: [ static entry — 1.M3  Java Custom Rules       | 2026-06-13 | Not Started ]
Row 20: [ static entry — R.M1  Literature Foundation   | 2026-06-20 | In Progress ]
Row 21: [ spacer ]
Row 22: [ ZONE 3b HEADER: "KEY CONSTRAINTS" ]
Row 23: [ constraint summary table — top 5 constraints ]
```

---

## Zone 1 — KPI Cards

Six KPI cells across columns A–F (row 5 = labels, row 6 = values).

| Cell | Label | Formula (row 6) |
|---|---|---|
| A5/A6 | Total Tasks | `=COUNTIF('Approach 1 - Semgrep PoC'!C:C,"TASK")+COUNTIF('Approach 2 - Hybrid LLM'!C:C,"TASK")+COUNTIF('Approach 3 - Agentic Scanner'!C:C,"TASK")+COUNTIF('Research'!C:C,"TASK")` |
| B5/B6 | Completed | Sum of COUNTIFS with status="Complete" across all 4 sheets |
| C5/C6 | In Progress | Sum of COUNTIFS with status="In Progress" across all 4 sheets |
| D5/D6 | Blocked | Sum of COUNTIFS with status="Blocked" across all 4 sheets |
| E5/E6 | Days to Deadline | `=DATE(2026,8,1)-TODAY()` |
| F5/F6 | % Complete | `=B6/A6` (formatted as percentage) |

**KPI cell styling:**
- Label cells (row 5): 12pt, bold, white text, `#2E5FA3` fill
- Value cells (row 6): 20pt, bold, black text, `#D6E4F0` fill, tall row (60px)

---

## Zone 2 — Progress by Goal

**Header row styling:** 12pt bold white on `#1F3864`

**Column headers:** Goal | Not Started | In Progress | Complete | Blocked | Total Tasks | % Done

**Row data (all formula-driven):**

### Row 10 — Approach 1: Semgrep PoC
| Col | Formula |
|---|---|
| Goal name | "Approach 1 — Semgrep PoC" (static label) |
| Not Started | `=COUNTIFS('Approach 1 - Semgrep PoC'!C:C,"TASK",'Approach 1 - Semgrep PoC'!K:K,"Not Started")` |
| In Progress | `=COUNTIFS('Approach 1 - Semgrep PoC'!C:C,"TASK",'Approach 1 - Semgrep PoC'!K:K,"In Progress")` |
| Complete | `=COUNTIFS('Approach 1 - Semgrep PoC'!C:C,"TASK",'Approach 1 - Semgrep PoC'!K:K,"Complete")` |
| Blocked | `=COUNTIFS('Approach 1 - Semgrep PoC'!C:C,"TASK",'Approach 1 - Semgrep PoC'!K:K,"Blocked")` |
| Total Tasks | `=COUNTIF('Approach 1 - Semgrep PoC'!C:C,"TASK")` |
| % Done | Complete / Total Tasks (formatted as %) |

Repeat the same formula pattern for rows 11 (Approach 2), 12 (Approach 3), 13 (Research).

### Row 14 — TOTAL
All columns sum rows 10–13. Bold, `#1F3864` fill, white font.

**Row styling:**
- Goal name column: 12pt bold, `#F5F5F5` fill
- Count columns: 12pt, status-colored fill matching the status they count
  - Not Started column: `#F5F5F5`
  - In Progress column: `#FFF3CD`
  - Complete column: `#D4EDDA`
  - Blocked column: `#F8D7DA`
- % Done column: 12pt bold, conditional — green if ≥ 80%, amber if 40–79%, red if < 40%

---

## Zone 3 — Upcoming Milestones

Static table (manually maintained when regenerating). Shows the 5 most immediately relevant milestones.

**Column headers:** Goal | Milestone ID | Milestone Name | Due Date | Status

| Goal | ID | Name | Due Date | Status |
|---|---|---|---|---|
| Approach 1 | 1.M2 | Python Custom Rules | 2026-06-11 | In Progress |
| Approach 1 | 1.M3 | Java Custom Rules | 2026-06-13 | Not Started |
| Approach 1 | 1.M4 | Test Codebase | 2026-06-16 | Not Started |
| Research | R.M1 | Literature Foundation | 2026-06-20 | In Progress |
| Approach 1 | 1.M5 | Demo Preparation | 2026-06-17 | Not Started |

**Row styling:** Alternating `#D6E4F0` / `#F5F5F5`, 12pt, status cell colored per status.

---

## Zone 3b — Key Constraints Summary

A compact 5-row summary of the highest-impact constraints (pulled from the Constraints sheet).

| ID | Constraint | Impact | Buffer Added |
|---|---|---|---|
| C-01 | No prior Go experience | High | +20% ML on Approach 2/3 Go tasks |
| C-03 | Approach 1 deadline Jun 20 — cannot slip | High | No buffer; fixed date |
| C-06 | Ollama model download 4–8 GB | Medium | 0.5–1 day setup before M6 LLM tasks |
| C-07 | Docker Desktop required for Approach 3 | Medium | 0.5 day setup buffer in 3.M4 |
| C-09 | Mentor review cycle 2–3 days | Medium | Explicit buffer rows in each approach |

---

## Dashboard Styling Summary

| Element | Size | Fill | Font |
|---|---|---|---|
| Sheet title | 20pt bold | `#1F3864` | White |
| Zone headers | 12pt bold | `#1F3864` | White |
| KPI labels | 12pt bold | `#2E5FA3` | White |
| KPI values | 20pt bold | `#D6E4F0` | Black |
| Table headers | 12pt bold | `#2E5FA3` | White |
| Table data | 12pt | Alternating / status | Black or status color |

No merged cells in data zones except zone headers (full-width merged).
Freeze panes: `A7` (KPI strip remains visible when scrolling).
