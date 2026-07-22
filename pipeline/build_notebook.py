import nbformat as nbf

nb = nbf.v4.new_notebook()
cells = []

cells.append(nbf.v4.new_markdown_cell("""\
# CloudGuardian — prioritization model

Reproduces the Week 2 prioritization pipeline: loads Prowler CSPM findings,
scores each FAIL finding on `severity x exposure x blast_radius`, and writes
the ranked results into `consolidated_findings.db` (SQLite).

Replace `data/sample_findings.csv` with your real Prowler export
(192 findings) to reproduce the full run — the scoring logic is identical,
this notebook just wraps `build_db.py` with inline visibility into each step.
"""))

cells.append(nbf.v4.new_code_cell("""\
import csv
import sqlite3
from pathlib import Path
from collections import Counter

import sys
PROJECT_ROOT = Path.cwd().parent if Path.cwd().name == "notebooks" else Path.cwd()
sys.path.insert(0, str(PROJECT_ROOT))
from build_db import (
    SEVERITY_WEIGHTS, EXPOSURE_RULES, BLAST_RADIUS_BY_RESOURCE_TYPE,
    score_exposure, score_blast_radius, load_and_score, write_db,
)

CSV_PATH = PROJECT_ROOT / "data/sample_findings.csv"
DB_PATH = PROJECT_ROOT / "db/consolidated_findings.db"
SCHEMA_PATH = PROJECT_ROOT / "db/schema.sql"
"""))

cells.append(nbf.v4.new_markdown_cell("## 1. Load raw findings"))
cells.append(nbf.v4.new_code_cell("""\
with CSV_PATH.open() as f:
    raw_rows = list(csv.DictReader(f))

print(f"{len(raw_rows)} total findings loaded from {CSV_PATH.name}")
print(Counter(r["status"] for r in raw_rows))
print(Counter(r["severity"] for r in raw_rows))
"""))

cells.append(nbf.v4.new_markdown_cell("""\
## 2. Scoring model

`priority_score = severity_score x exposure_score x blast_radius`

- **severity_score** — Prowler's own severity, weighted 1-10
- **exposure_score** — keyword-matched against the check_id (public access,
  open ingress, missing MFA, etc. score highest)
- **blast_radius** — fixed per resource type (IAM/RDS score highest — a
  compromised credential or database has the widest downstream impact)
"""))

cells.append(nbf.v4.new_code_cell("""\
print("Severity weights:", SEVERITY_WEIGHTS)
print()
print("Exposure rules (keyword -> score):")
for kw, score in EXPOSURE_RULES:
    print(f"  {kw:<35} {score}")
print()
print("Blast radius by resource type:", BLAST_RADIUS_BY_RESOURCE_TYPE)
"""))

cells.append(nbf.v4.new_markdown_cell("## 3. Score and rank"))
cells.append(nbf.v4.new_code_cell("""\
scored_rows = load_and_score(CSV_PATH)
fails = [r for r in scored_rows if r["status"].upper() == "FAIL"]

print(f"{len(fails)} FAIL findings ranked by priority\\n")
print(f"{'Rank':<5}{'Score':<8}{'Sev':<10}{'MC':<7}{'Check':<45}")
for r in fails:
    print(f"{r['priority_rank']:<5}{r['priority_score']:<8.0f}{r['severity']:<10}"
          f"{(r['misconfig_id'] or '-'): <7}{r['check_id'][:44]:<45}")
"""))

cells.append(nbf.v4.new_markdown_cell("## 4. Persist to the consolidated findings database"))
cells.append(nbf.v4.new_code_cell("""\
write_db(scored_rows, DB_PATH, SCHEMA_PATH)
print(f"Wrote {len(scored_rows)} findings to {DB_PATH}")
"""))

cells.append(nbf.v4.new_markdown_cell("## 5. Verify — query back from SQLite"))
cells.append(nbf.v4.new_code_cell("""\
conn = sqlite3.connect(DB_PATH)
top = conn.execute('''
    SELECT priority_rank, severity, misconfig_id, priority_score, title
    FROM findings
    WHERE status = "FAIL"
    ORDER BY priority_rank
    LIMIT 10
''').fetchall()

for row in top:
    print(row)

conn.close()
"""))

cells.append(nbf.v4.new_markdown_cell("""\
## 6. Next step: remediation

For each top-ranked finding with a `misconfig_id`, the corresponding prompt
in `prompts/prompt_library.md` generates the remediation guidance, which
feeds either an auto-remediation Lambda (guardrailed, reversible changes)
or the human-approval queue (higher-risk changes like IAM/network access).
See `../lambdas/` for the remediation functions.
"""))

nb['cells'] = cells
with open('notebooks/prioritization_model.ipynb', 'w') as f:
    nbf.write(nb, f)

print("Notebook written.")
