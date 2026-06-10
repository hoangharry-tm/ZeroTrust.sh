import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter

wb = openpyxl.Workbook()
ws = wb.active
ws.title = "Execution Overview"

# ── Palette ──────────────────────────────────────────────────────────────────
DARK_BLUE   = "1F3864"
MID_BLUE    = "2E5FA3"
LIGHT_BLUE  = "D6E4F0"
ACCENT_GOLD = "C9A84C"
WHITE       = "FFFFFF"
LIGHT_GRAY  = "F5F5F5"
MID_GRAY    = "CCCCCC"

def side(color=MID_GRAY, style="thin"):
    return Side(border_style=style, color=color)

def border(all_sides=MID_GRAY):
    s = side(all_sides)
    return Border(left=s, right=s, top=s, bottom=s)

def fill(hex_color):
    return PatternFill("solid", fgColor=hex_color)

def font(bold=False, color=None, size=11, italic=False):
    return Font(bold=bold, color=color or "000000", size=size, italic=italic,
                name="Calibri")

def align(h="left", v="center", wrap=True):
    return Alignment(horizontal=h, vertical=v, wrap_text=wrap)

# ── Data ─────────────────────────────────────────────────────────────────────
rows = [
    # (date, milestone, tasks, status)
    ("2026-06-09", "M-1  Research & Setup",
     "Install Semgrep CLI · Read YAML rule docs · Write one toy rule end-to-end · Scaffold repo (rules/ tests/ scripts/)",
     "Complete"),

    ("2026-06-10", "M-2  Python Custom Rules (Day 1 of 2)",
     "Write custom rules: LLM prompt injection (OpenAI / Anthropic / LangChain) · AI bypass comment detection · Set up bad.py / ok.py test pairs",
     "In Progress"),

    ("2026-06-11", "M-2  Python Custom Rules (Day 2 of 2)",
     "Write custom rule: hardcoded AI service API keys (sk- / sk-ant- / hf_) · Configure community rule packs (p/python, p/owasp-top-ten) · Tune false positive rate with pattern-not",
     ""),

    ("2026-06-12", "M-3  Java Custom Rules (Day 1 of 2)",
     "Validate Java AST shapes with semgrep --dump-ast · Write custom rule: AI bypass comments (Java) · Write custom rule: hardcoded AI service credentials in Java",
     ""),

    ("2026-06-13", "M-3  Java Custom Rules (Day 2 of 2)",
     "Configure community rule packs (p/java, p/java-security-audit) · Tune rules against bad.java / ok.java test pairs · Document precision-recall tradeoff per rule",
     ""),

    ("2026-06-16", "M-4  Test Codebase",
     "AI-generate fake Spring Boot REST API (10–15 files, 800–1 200 LOC) · Embed ≥8 intentional vulnerabilities · Run full rule set · Document detection rate and false positive count",
     ""),

    ("2026-06-17", "M-5  Demo Preparation",
     "Write demo/run_demo.sh with pinned Semgrep version · Full dry-run in fresh terminal · Record 3-minute fallback video",
     ""),

    ("2026-06-18", "M-6  Presentation Narrative",
     "Write pros / cons of Semgrep-only approach · Draft next-step argument for Approach 2 (LLM Verifier + Path B) · Add speaker notes",
     ""),

    ("2026-06-19", "M-7  Jupyter Notebook  (Bonus)",
     "Precision and recall per rule · Scan speed (lines/second) · AI-specific detection rate · False positive rate on clean codebase · Charts",
     ""),

    ("2026-06-20", "Presentation",
     "Live CLI demo + narrative delivery to tech lead · Collect approval or actionable feedback",
     ""),
]

# ── Sheet title ───────────────────────────────────────────────────────────────
ws.merge_cells("A1:E1")
title_cell = ws["A1"]
title_cell.value = "ZeroTrust.sh  ·  Approach 1 (Semgrep PoC)  ·  Executive Timeline"
title_cell.font = Font(bold=True, color=WHITE, size=14, name="Calibri")
title_cell.fill = fill(DARK_BLUE)
title_cell.alignment = align("center", "center")
title_cell.border = border(DARK_BLUE)
ws.row_dimensions[1].height = 30

# ── Sub-header ────────────────────────────────────────────────────────────────
ws.merge_cells("A2:E2")
sub = ws["A2"]
sub.value = "Intern: Ton Minh Hoang  ·  VNG ZingPlay Studio  ·  Deadline: 2026-06-20"
sub.font = Font(italic=True, color=WHITE, size=10, name="Calibri")
sub.fill = fill(MID_BLUE)
sub.alignment = align("center", "center")
sub.border = border(MID_BLUE)
ws.row_dimensions[2].height = 18

# blank spacer
ws.row_dimensions[3].height = 6

# ── Column headers ────────────────────────────────────────────────────────────
headers = ["Date", "Milestone", "Tasks", "Status", "Notes"]
col_widths = [14, 30, 70, 14, 22]

for col_idx, (header, width) in enumerate(zip(headers, col_widths), start=1):
    cell = ws.cell(row=4, column=col_idx, value=header)
    cell.font = Font(bold=True, color=WHITE, size=11, name="Calibri")
    cell.fill = fill(MID_BLUE)
    cell.alignment = align("center", "center", wrap=False)
    cell.border = border(MID_BLUE)
    ws.column_dimensions[get_column_letter(col_idx)].width = width

ws.row_dimensions[4].height = 22

# ── Data rows ─────────────────────────────────────────────────────────────────
for row_num, (date, milestone, tasks, status) in enumerate(rows, start=5):
    is_even = (row_num % 2 == 0)
    row_fill = fill(LIGHT_BLUE if is_even else LIGHT_GRAY)

    # highlight presentation row
    is_presentation = "Presentation" in milestone and "M-" not in milestone
    if is_presentation:
        row_fill = fill("FFF3CD")  # warm yellow

    # highlight bonus row
    is_bonus = "Bonus" in milestone
    if is_bonus:
        row_fill = fill("EAF4EA")  # soft green

    values = [date, milestone, tasks, status, ""]
    for col_idx, value in enumerate(values, start=1):
        cell = ws.cell(row=row_num, column=col_idx, value=value)
        cell.fill = row_fill
        cell.border = border()
        cell.alignment = align("left", "center", wrap=True)
        cell.font = font(size=10)

        if col_idx == 1:  # date col
            cell.font = font(bold=True, size=10)
            cell.alignment = align("center", "center", wrap=False)

        if col_idx == 2:  # milestone col
            cell.font = font(bold=True, size=10,
                             color=ACCENT_GOLD if is_presentation else "000000")

        if col_idx == 4 and value == "Complete":
            cell.font = font(bold=True, color="1E7B34", size=10)
        elif col_idx == 4 and value == "In Progress":
            cell.font = font(bold=True, color="B45309", size=10)

    ws.row_dimensions[row_num].height = 42

# ── Legend ────────────────────────────────────────────────────────────────────
legend_row = len(rows) + 6
ws.merge_cells(f"A{legend_row}:E{legend_row}")
legend = ws[f"A{legend_row}"]
legend.value = (
    "Status key:  Complete = delivered  ·  In Progress = active  "
    "·  (blank) = not started  ·  Bonus milestone is time-permitting only"
)
legend.font = Font(italic=True, color="666666", size=9, name="Calibri")
legend.alignment = align("left", "center")

# ── Freeze panes & row height ─────────────────────────────────────────────────
ws.freeze_panes = "A5"

# ── Research Papers Sheet ─────────────────────────────────────────────────────
ws2 = wb.create_sheet(title="Research Papers")

ws2.merge_cells("A1:G1")
t2 = ws2["A1"]
t2.value = "ZeroTrust.sh  ·  Related Research Papers"
t2.font = Font(bold=True, color=WHITE, size=14, name="Calibri")
t2.fill = fill(DARK_BLUE)
t2.alignment = align("center", "center")
t2.border = border(DARK_BLUE)
ws2.row_dimensions[1].height = 30

ws2.merge_cells("A2:G2")
s2 = ws2["A2"]
s2.value = "Compiled: 2026-06-10  ·  Sources: arXiv · ACM · IEEE · USENIX · Semantic Scholar"
s2.font = Font(italic=True, color=WHITE, size=10, name="Calibri")
s2.fill = fill(MID_BLUE)
s2.alignment = align("center", "center")
s2.border = border(MID_BLUE)
ws2.row_dimensions[2].height = 18

ws2.row_dimensions[3].height = 6

headers2 = ["#", "Title", "Authors", "Year", "Venue", "Relevance to ZeroTrust.sh", "URL"]
col_widths2 = [5, 62, 22, 7, 28, 55, 45]

for ci, (h, w) in enumerate(zip(headers2, col_widths2), start=1):
    cell = ws2.cell(row=4, column=ci, value=h)
    cell.font = Font(bold=True, color=WHITE, size=11, name="Calibri")
    cell.fill = fill(MID_BLUE)
    cell.alignment = align("center", "center", wrap=False)
    cell.border = border(MID_BLUE)
    ws2.column_dimensions[get_column_letter(ci)].width = w
ws2.row_dimensions[4].height = 22
ws2.freeze_panes = "A5"

paper_areas = [
    ("AREA 1 — Deep Learning & ML for Vulnerability Detection", [
        (1,  "Automated Vulnerability Detection in Source Code Using Deep Representation Learning", "Feng et al.", "2026", "arXiv", "CNN-based deep representation learning for vulnerability detection — validates ML classifier gate in Path B Tier 2", "https://arxiv.org/abs/2602.23121"),
        (2,  "DiverseVul: A New Vulnerable Source Code Dataset for Deep Learning Based Vulnerability Detection", "Jia et al.", "2023", "RAID 2023 / ACM", "Largest diverse C/C++ vulnerability dataset (18,945 functions, 150 CWEs) — training data source for Code Vulnerability Classifier", "https://arxiv.org/abs/2304.00409"),
        (3,  "Vulnerability Detection in C/C++ Code with Deep Learning", "Multiple authors", "2024", "arXiv", "Neural networks with program slices for vulnerability detection — informs Tier 2 classifier design", "https://arxiv.org/abs/2405.12384"),
        (4,  "Deep Learning Aided Software Vulnerability Detection: A Survey", "Survey authors", "2025", "arXiv", "Comprehensive DL survey for vulnerability detection — baseline reference for Tier 2 classifier selection", "https://arxiv.org/abs/2503.04002"),
    ]),
    ("AREA 2 — Graph Neural Networks for Vulnerability Detection", [
        (5,  "Software Vulnerability Detection Using a Lightweight Graph Neural Network (VulGNN)", "Zhu et al.", "2026", "arXiv", "Lightweight GNN achieving LLM-parity at 100x smaller size — validates cheap local classifier concept in new architecture", "https://arxiv.org/abs/2603.29216"),
        (6,  "Vul-LMGNNs: Fusing Language Models and Graph Neural Networks for Code Vulnerability Detection", "Rong et al.", "2024", "arXiv", "Hybrid code LM + GNN — informs Call Graph + Classifier integration in Path B Tier 2", "https://arxiv.org/abs/2404.14719"),
        (7,  "Structure-Aware Code Vulnerability Analysis With Graph Neural Networks", "Allamanis et al.", "2024", "arXiv", "GNN-based vulnerability analysis using Java vulnerability-fixing commits — informs structure-aware detection", "https://arxiv.org/abs/2307.11454"),
        (8,  "Graph Neural Networks for Vulnerability Detection: A Counterfactual Explanation", "Li et al.", "2024", "arXiv", "Explainability analysis of GNN detection — informs confidence scoring in Dedup layer", "https://arxiv.org/abs/2404.15687"),
        (9,  "ReGVD: Revisiting Graph Neural Networks for Vulnerability Detection", "Nguyen et al.", "2022", "ACM/IEEE", "Foundational GNN model treating source code as flat token sequences — baseline for Tier 2 classifier", "https://dl.acm.org/doi/abs/10.1145/3510454.3516865"),
        (10, "LineVD: Statement-level Vulnerability Detection using Graph Neural Networks", "Chen et al.", "2022", "arXiv", "Fine-grained GNN vulnerability localization — informs line-level finding output in HTML report", "https://arxiv.org/abs/2203.05181"),
    ]),
    ("AREA 3 — LLM for Code Security Analysis", [
        (11, "LLMs in Code Vulnerability Analysis: A Proof of Concept", "Kochling et al.", "2026", "arXiv", "Empirical PoC for LLM vulnerability analysis — validates LLM Semantic Scan role in Path B Tier 3", "https://arxiv.org/abs/2601.08691"),
        (12, "IRIS: LLM-Assisted Static Analysis for Detecting Security Vulnerabilities", "Scanlon et al.", "2024", "arXiv", "Hybrid SAST+LLM detecting 55/120 vulns + 6 new, reducing FP by 80% — directly validates ZeroTrust.sh hybrid design", "https://arxiv.org/abs/2405.17238"),
        (13, "Large Language Model for Vulnerability Detection and Repair: Literature Review and the Road Ahead", "Zhang et al.", "2025", "ACM TOSEM", "Comprehensive LLM vulnerability + repair survey — informs patch generation design across all approaches", "https://dl.acm.org/doi/10.1145/3708522"),
        (14, "Understanding the Effectiveness of LLMs in Detecting Security Vulnerabilities", "Steenhoek et al.", "2023", "arXiv", "Systematic LLM evaluation with prompting strategy analysis — informs LLM Verifier prompt design in Path A", "https://arxiv.org/abs/2311.16169"),
        (15, "Large Language Models for Source Code Analysis: Applications, Models and Datasets", "Sharma et al.", "2025", "arXiv", "Survey of LLM architectures for code analysis — model selection reference for LLM components", "https://arxiv.org/abs/2503.17502"),
        (16, "Can Large Language Models Find And Fix Vulnerable Software?", "Pearce et al.", "2023", "arXiv", "Empirical evaluation of LLM detection + repair — validates dual-role LLM use in Approaches 2 and 3", "https://arxiv.org/abs/2308.10345"),
    ]),
    ("AREA 4 — Hybrid Static Analysis + LLM", [
        (17, "LLM-Driven SAST-Genius: A Hybrid Static Analysis Framework for Comprehensive and Actionable Security", "Multiple authors", "2024", "arXiv", "Hybrid SAST+LLM reducing FP by 91% (225→20 alerts) vs Semgrep alone — strongest validation of ZeroTrust.sh architecture", "https://arxiv.org/abs/2509.15433"),
        (18, "ZeroFalse: Improving Precision in Static Analysis with LLMs", "Scanlon et al.", "2024", "arXiv", "LLM false positive reduction in static analysis — validates LLM Verifier design in Path A", "https://arxiv.org/abs/2510.02534"),
        (19, "Combining Large Language Models with Static Analyzers for Code Review Generation", "Jaoua et al.", "2025", "arXiv", "LLM + static analysis for code review — informs patch suggestion output format", "https://arxiv.org/abs/2502.06633"),
        (20, "A Contemporary Survey of LLM-Assisted Program Analysis", "Survey authors", "2025", "arXiv", "Comprehensive survey of LLM program analysis techniques — architecture reference for all three approaches", "https://arxiv.org/abs/2502.18474"),
        (21, "RepoAudit: An Autonomous LLM-Agent for Repository-Level Code Auditing", "Li et al.", "2025", "arXiv", "LLM-agent for repo-level auditing — informs Approach 3 multi-agent orchestration design", "https://arxiv.org/abs/2501.18160"),
    ]),
    ("AREA 5 — AI-Generated Code Security & Prompt Injection", [
        (22, "Security Vulnerabilities in AI-Generated Code: A Large-Scale Analysis of Public GitHub Repositories", "Zhao et al.", "2024", "IEEE/ACM", "4,241 CWE instances across AI-generated code from 4 tools — empirical validation of the core ZeroTrust.sh problem statement", "https://arxiv.org/abs/2510.26103"),
        (23, "Prompt Injection Attacks on Agentic Coding Assistants: A Systematic Analysis", "Yang et al.", "2026", "arXiv", "85%+ attack success rates for prompt injection in agentic assistants — validates ZeroTrust.sh AI-specific threat detection", "https://arxiv.org/abs/2601.17548"),
        (24, "Security Degradation in Iterative AI Code Generation: A Systematic Analysis of the Paradox", "Multiple authors", "2025", "IEEE-ISTAS", "Iterative LLM interactions without human review introduce new vulnerabilities — validates vibe-coding threat model", "https://arxiv.org/abs/2506.11022"),
        (25, "Assessing the Quality and Security of AI-Generated Code: A Quantitative Analysis", "Multiple authors", "2024", "arXiv", "Quantitative security analysis of AI-generated code — market validation and threat taxonomy reference", "https://arxiv.org/abs/2508.14727"),
        (26, "You Still Have to Study: On the Security of LLM Generated Code", "Ferrara et al.", "2024", "arXiv", "36–40% of Copilot code contains CWE vulnerabilities — key statistic for product positioning and pitch", "https://arxiv.org/abs/2408.07106"),
    ]),
    ("AREA 6 — Token Cost Optimization for LLM Pipelines", [
        (27, "FrugalGPT: How to Use Large Language Models While Reducing Cost and Improving Performance", "Eisingerich et al.", "2023", "arXiv", "Cascade routing achieving 98% cost savings — theoretical foundation for Cascading Intelligence architecture", "https://arxiv.org/abs/2305.05176"),
        (28, "Batch Prompting: Efficient Inference with Large Language Model APIs", "Rajkumar et al.", "2023", "arXiv", "Batch processing reducing LLM token costs up to 5x — informs Token Budget Controller batching strategy", "https://arxiv.org/abs/2301.08721"),
        (29, "Token Sugar: Making Source Code Sweeter for LLMs through Token-Efficient Shorthand", "Multiple authors", "2025", "arXiv", "Token optimization for code representation — informs context chunking in Token Budget Controller", "https://arxiv.org/abs/2512.08266"),
        (30, "Learning to Focus: Context Extraction for Efficient Code Vulnerability Detection with Language Models", "Dittmann et al.", "2025", "arXiv", "Context filtering for reducing LLM token consumption in vulnerability detection — directly validates Token Budget Controller", "https://arxiv.org/abs/2505.17460"),
    ]),
    ("AREA 7 — Call Graph, Taint Analysis & Code Representations", [
        (31, "Vulnerability Detection with Interprocedural Context in Multiple Languages: Assessing Effectiveness and Cost", "Gharibi et al.", "2024", "arXiv", "Interprocedural analysis impact on LLM detection across languages — validates Call Graph + CVE Enrichment in Path B", "https://arxiv.org/abs/2604.08417"),
        (32, "Multi-Agent Taint Specification Extraction for Vulnerability Detection", "Zhang et al.", "2026", "arXiv", "Multi-agent LLM + taint analysis — informs Approach 3 multi-agent architecture with CodeQL/Joern integration", "https://arxiv.org/abs/2601.10865"),
        (33, "LLMxCPG: Context-Aware Vulnerability Detection Through Code Property Graph-Guided LLMs", "Pan et al.", "2024", "arXiv", "CPG-guided LLM for context-aware detection — informs CPG integration in Path B call graph analysis", "https://arxiv.org/abs/2507.16585"),
        (34, "Bridging Code Property Graphs and Language Models for Program Analysis", "Mahfouz et al.", "2026", "arXiv", "Framework bridging CPG and LLMs — validates hybrid CPG+LLM design in Path B", "https://arxiv.org/abs/2603.24837"),
        (35, "Enhancing Software Vulnerability Detection Using Code Property Graphs and Convolutional Neural Networks", "Multiple authors", "2025", "arXiv", "CPG+CNN for local and global code structure — informs Code Classifier training in new architecture", "https://arxiv.org/abs/2503.18175"),
        (36, "VulTrLM: LLM-Assisted Vulnerability Detection via AST Decomposition and Comment Enhancement", "Liu et al.", "2025", "Empirical Software Engineering", "LLM-assisted AST decomposition for semantic enhancement — informs AST preprocessing in Path B Tier 1", "https://dl.acm.org/doi/10.1007/s10664-025-10738-7"),
        (37, "Dataflow Analysis-Inspired Deep Learning for Efficient Vulnerability Detection", "Cheng et al.", "2022", "arXiv", "Dataflow analysis-inspired DL approach — validates dataflow integration in Path A CodeQL/Joern", "https://arxiv.org/abs/2212.08108"),
        (38, "Reducing False Positives in Static Bug Detection with LLMs: An Empirical Study in Industry", "Dittmann et al.", "2026", "arXiv", "Industrial study on LLM false positive reduction — validates LLM Verifier design in Path A at production scale", "https://arxiv.org/abs/2601.18844"),
        (39, "LSAST: Enhancing Cybersecurity through LLM-supported Static Application Security Testing", "Multiple authors", "2024", "arXiv", "Locally-hostable LLM for SAST without cloud APIs — validates privacy-first local LLM deployment approach", "https://arxiv.org/abs/2409.15735"),
        (40, "Software Vulnerability Analysis Across Programming Language and Program Representation Landscapes: A Survey", "Multiple authors", "2025", "arXiv", "Survey of AST, CFG, PDG, CPG representations — reference for program representation selection across all approaches", "https://arxiv.org/abs/2503.20244"),
    ]),
]

current_row = 5
for area_name, papers in paper_areas:
    ws2.merge_cells(f"A{current_row}:G{current_row}")
    ah = ws2[f"A{current_row}"]
    ah.value = area_name
    ah.font = Font(bold=True, color=WHITE, size=11, name="Calibri")
    ah.fill = fill(DARK_BLUE)
    ah.alignment = align("left", "center", wrap=False)
    ah.border = border(DARK_BLUE)
    ws2.row_dimensions[current_row].height = 20
    current_row += 1

    for num, title, authors, year, venue, relevance, url in papers:
        is_even = (current_row % 2 == 0)
        row_fill = fill(LIGHT_BLUE if is_even else LIGHT_GRAY)
        for ci, value in enumerate([num, title, authors, year, venue, relevance, url], start=1):
            cell = ws2.cell(row=current_row, column=ci, value=value)
            cell.fill = row_fill
            cell.border = border()
            cell.alignment = align("left", "center", wrap=True)
            cell.font = font(size=10)
            if ci == 1:
                cell.alignment = align("center", "center", wrap=False)
                cell.font = font(bold=True, size=10)
            if ci == 4:
                cell.alignment = align("center", "center", wrap=False)
        ws2.row_dimensions[current_row].height = 42
        current_row += 1

    current_row += 1  # blank spacer between areas

# ── Save ──────────────────────────────────────────────────────────────────────
out = "docs/execution-overview.xlsx"
wb.save(out)
print(f"Saved: {out}")
