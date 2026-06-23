#!/usr/bin/env python3
"""Generate fixture coverage report — run from repo root."""
import os, re

RULES = [
    ("python", "*.yaml"),
    ("java", "*.yaml"),
    ("generic", "*.yaml"),
    ("astgrep", "*.yaml"),
]

def main():
    bad_dir = "testdata/rules-tests/bad"
    ok_dir = "testdata/rules-tests/ok"
    ko_dir = "testdata/rules-tests/knockout"

    print("# Fixture Coverage Report\n")
    print(f"**Generated:** $(date)  \n")
    print(f"**Bad:** {len(os.listdir(bad_dir))}  **Ok:** {len(os.listdir(ok_dir))}  **Knockout:** {len(os.listdir(ko_dir))}\n")

    for lang, glob_pat in RULES:
        rule_dir = f"rules/{lang}"
        if not os.path.isdir(rule_dir):
            continue
        section = "OpenGrep" if lang != "astgrep" else "ast-grep"
        lang_label = {"python": "Python", "java": "Java", "generic": "Generic", "astgrep": "Multi-lang"}[lang]
        print(f"## {section} — {lang_label}\n")
        print("| Rule | Sub-rules | Bad | Ok | TP | FP | KO |")
        print("|------|-----------|-----|----|----|----|-----|")

        for rule_file in sorted(os.listdir(rule_dir)):
            if not rule_file.endswith(".yaml"):
                continue
            rule_path = os.path.join(rule_dir, rule_file)
            rid = rule_file.replace(".yaml", "")
            prefix = re.match(r'^[A-Z]+-[0-9]+', rid)
            prefix = prefix.group(0) if prefix else rid

            with open(rule_path) as f:
                content = f.read()
            sub_count = max(0, len(re.findall(r'^\s+-\s+id:\s+\S+', content, re.MULTILINE)))

            bad = [f for f in os.listdir(bad_dir) if f.startswith(prefix)]
            ok = [f for f in os.listdir(ok_dir) if f.startswith(prefix)]
            print(f"| {rid} | {sub_count} | {len(bad)} | {len(ok)} | TODO | TODO | TODO |")

    print("\n## Notes")
    print("- TP/FP/KO columns require running `scripts/test_rules.sh`")

if __name__ == "__main__":
    main()
