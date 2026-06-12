import openpyxl
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from sheets.dashboard import build_dashboard
from sheets.goals import build_goal_sheet
from sheets.constraints import build_constraints
from sheets.research_papers import build_research_papers
from sheets.data_g1 import goal1_data
from sheets.data_g2 import goal2_data
from sheets.data_g3 import goal3_data
from sheets.data_g4 import goal4_data
from sheets.data_research import research_data
from sheets.data_constraints import constraints_data
from sheets.data_papers import papers


def main():
    wb = openpyxl.Workbook()

    build_dashboard(wb)

    build_goal_sheet(
        wb,
        "ZeroTrust.sh  ·  G1 — Foundation & Detection Scaffold",
        "Intern: Ton Minh Hoang  ·  VNG ZingPlay Studio  ·  Goal: Rule suite + Go CLI + Ingestion layer + Finding schema  ·  Deadline: 2026-06-27",
        "G1 - Foundation",
        goal1_data,
    )

    build_goal_sheet(
        wb,
        "ZeroTrust.sh  ·  G2 — Path A: CPG + Taint + LLM Verifier",
        "Intern: Ton Minh Hoang  ·  VNG ZingPlay Studio  ·  Goal: Joern CPG + taint queries + Python worker IPC + LLM Verifier  ·  Deadline: 2026-07-18",
        "G2 - Path A",
        goal2_data,
    )

    build_goal_sheet(
        wb,
        "ZeroTrust.sh  ·  G3 — Path B: Three-Tier Semantic Cost Funnel",
        "Intern: Ton Minh Hoang  ·  VNG ZingPlay Studio  ·  Goal: Heuristic Targeting + UniXcoder + Semantic Summarizer + LLM ReAct  ·  Deadline: 2026-08-01",
        "G3 - Path B",
        goal3_data,
    )

    build_goal_sheet(
        wb,
        "ZeroTrust.sh  ·  G4 — Integration, Report & Demo",
        "Intern: Ton Minh Hoang  ·  VNG ZingPlay Studio  ·  Goal: Dedup + SSVC scoring + HTML report + end-to-end demo  ·  Deadline: 2026-08-06",
        "G4 - Integration",
        goal4_data,
    )

    build_goal_sheet(
        wb,
        "ZeroTrust.sh  ·  Scientific Research & Architecture Validation",
        "Intern: Ton Minh Hoang  ·  VNG ZingPlay Studio  ·  Goal: Evidence-backed architecture validation  ·  Runs Jun 9 – Aug 1",
        "Research",
        research_data,
    )

    build_constraints(wb, constraints_data)
    build_research_papers(wb, papers)

    out = "docs/ZeroTrust_Internship_Roadmap.xlsx"
    wb.save(out)
    print(f"Roadmap Excel workbook successfully generated at: {out}")


if __name__ == "__main__":
    main()
