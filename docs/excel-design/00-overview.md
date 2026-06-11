# ZeroTrust.sh — Excel Workbook Design Overview

**File:** `docs/execution-overview.xlsx`
**Generator:** `docs/generate_overview.py`
**Last designed:** 2026-06-11

---

## Purpose

The workbook is the single executive-facing artifact for the ZeroTrust.sh 8-week internship. It tracks all four goals — three implementation approaches plus a scientific research thread — in a way that is readable by both the intern (task-level detail) and a non-technical manager (dashboard KPIs).

---

## Sheet Index

| # | Sheet Name | Type | Purpose |
|---|---|---|---|
| 1 | `Dashboard` | Summary | Live KPI strip, progress table, upcoming milestones — all synced via formulas |
| 2 | `Approach 1 - Semgrep PoC` | Plan | Goal 1 — Semgrep PoC, Jun 9–20 |
| 3 | `Approach 2 - Hybrid LLM` | Plan | Goal 2 — Hybrid AST + Local LLM Scanner, Jun 23–Jul 28 |
| 4 | `Approach 3 - Agentic Scanner` | Plan | Goal 3 — Agentic Scanner + Proof-of-Exploit, Jul 21–Aug 1 |
| 5 | `Research` | Plan | Goal R — Scientific Research & Architecture Validation, Jun 9–Aug 1 |
| 6 | `Constraints` | Register | 10 planning constraints with category, impact, and buffer applied |
| 7 | `Research Papers` | Catalogue | 40 academic papers across 7 research areas (existing, unchanged) |

---

## Row Hierarchy (Approach + Research sheets)

Every Approach and Research sheet follows a strict three-level hierarchy:

```
GOAL HEADER ROW          full-width merged cell, dark navy background, 20pt bold white
  MILESTONE ROW          blue background, 12pt bold white, ID like 1.M1
    TASK ROW             alternating light blue / light gray, 12pt, ID like 1.M1.T1
    TASK ROW
    ...
  BUFFER ROW             amber-tinted background, 12pt italic, labeled "Explicit Buffer"
  MILESTONE ROW
    ...
```

- **MILESTONE** rows carry aggregate PERT O / ML / P / E values for the whole block.
- **TASK** rows carry individual PERT O / ML / P values; PERT E is computed as `(O + 4×ML + P) / 6`.
- **BUFFER** rows are explicit named rows — buffer is never hidden inside task estimates.
- **BONUS** milestones use a soft-green background to signal "cut first if schedule slips."

---

## Column Schema (all Approach + Research sheets)

| Col | Letter | Header | Width (chars) | Notes |
|---|---|---|---|---|
| 1 | A | ID | 14 | `1.M1` for milestones, `1.M1.T1` for tasks |
| 2 | B | Name | 52 | Tasks indented with 4 leading spaces |
| 3 | C | Type | 13 | `MILESTONE`, `TASK`, or `BUFFER` |
| 4 | D | Start Date | 13 | `YYYY-MM-DD`; blank for task rows |
| 5 | E | End Date | 13 | `YYYY-MM-DD`; blank for task rows |
| 6 | F | PERT O (h) | 11 | Optimistic hours |
| 7 | G | PERT ML (h) | 11 | Most Likely hours |
| 8 | H | PERT P (h) | 11 | Pessimistic hours |
| 9 | I | PERT E (h) | 11 | Expected = (O + 4×ML + P) / 6 |
| 10 | J | Actual Hrs | 12 | Filled as work progresses |
| 11 | K | Status | 17 | Status value (drives cell color) |
| 12 | L | Owner | 10 | Always "Hoang" |
| 13 | M | Notes | 38 | Blockers, decisions, context |

---

## Typography Rules

| Element | Font Size | Style | Color |
|---|---|---|---|
| Sheet title row (row 1) | 20pt | Bold | White on `#1F3864` |
| Column header row (row 4) | 20pt | Bold | White on `#2E5FA3` |
| Milestone name (col B) | 12pt | Bold | White (or dark if bonus/buffer) |
| Task name (col B) | 12pt | Regular | Black |
| Buffer row (col B) | 12pt | Italic | `#5C4B00` on `#FFF9E6` |
| All other data cells | 12pt | Regular | Per status color |

Font family: **Calibri** throughout.

---

## Status Color Semantics

| Status | Fill | Font Color | Applies to |
|---|---|---|---|
| `Complete` | `#D4EDDA` | `#1E7B34` | Status cell + row (tasks) |
| `In Progress` | `#FFF3CD` | `#B45309` | Status cell + row (tasks) |
| `Blocked` | `#F8D7DA` | `#842029` | Status cell |
| `At Risk` | `#FFE5B4` | `#8B4513` | Status cell |
| `Not Started` | `#F5F5F5` | `#666666` | Status cell |
| Milestone row | `#2E5FA3` | `#FFFFFF` | Entire row |
| Bonus milestone | `#EAF4EA` | `#1E5924` | Entire row |
| Buffer row | `#FFF9E6` | `#5C4B00` | Entire row |
| Col header | `#2E5FA3` | `#FFFFFF` | Entire header row |
| Sheet title | `#1F3864` | `#FFFFFF` | Merged title row |

---

## Row Height Standards

| Row type | Height (px) |
|---|---|
| Sheet title (row 1) | 50 |
| Subtitle (row 2) | 22 |
| Spacer (row 3) | 6 |
| Column header (row 4) | 50 |
| Milestone rows | 40 |
| Task rows | 45 |
| Between-milestone spacers | 5 |

---

## PERT Estimation Method

```
E = (O + 4 × ML + P) / 6
σ = (P − O) / 6
```

- **O** = Optimistic: everything works, AI assistance is perfect
- **ML** = Most Likely: normal progress, 1–2 debug cycles
- **P** = Pessimistic: tool quirks, learning curve surprises, blocked states

**Applied adjustments:**
- Go learning curve (Approach 2, M1–M3): ML × 1.20
- LangGraph learning curve (Approach 3, M3): ML × 1.15
- Java rules take ~20% longer than Python equivalents (Approach 1)

---

## Freeze Panes & Print Area

- **Freeze:** Row 4 (column headers) — panes freeze at `A5` on every sheet
- **Print area:** Set to `A1:M{last_data_row}` on each sheet

---

## Dashboard Sync Rules

The Dashboard sheet must never contain manually entered numbers. All KPI values are driven by `COUNTIFS` formulas referencing the Status column (column K) and Type column (column C) of the four plan sheets.

Example formula pattern:
```
Total completed tasks =
  COUNTIFS('Approach 1 - Semgrep PoC'!C:C,"TASK",'Approach 1 - Semgrep PoC'!K:K,"Complete")
+ COUNTIFS('Approach 2 - Hybrid LLM'!C:C,"TASK",'Approach 2 - Hybrid LLM'!K:K,"Complete")
+ COUNTIFS('Approach 3 - Agentic Scanner'!C:C,"TASK",'Approach 3 - Agentic Scanner'!K:K,"Complete")
+ COUNTIFS('Research'!C:C,"TASK",'Research'!K:K,"Complete")
```

---

## Generator Script Conventions

- All palette constants defined at top of script as hex strings (no `#` prefix for openpyxl)
- One function per sheet: `build_dashboard()`, `build_approach_sheet()`, `build_constraints()`, `build_research_papers()`
- `build_approach_sheet()` is generic — called for sheets 2–5 with different data
- PERT E computed in Python (`(O + 4*ML + P) / 6`) and written as a number, not an Excel formula
- Dashboard KPI cells written as Excel formula strings (`=COUNTIFS(...)`)
