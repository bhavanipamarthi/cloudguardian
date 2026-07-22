# CloudGuardian — findings database, prioritization notebook, prompt library

## What's here

| Path | Deliverable |
|---|---|
| `db/schema.sql`, `build_db.py`, `db/consolidated_findings.db` | Consolidated CSPM findings database |
| `notebooks/prioritization_model.ipynb` | Prioritization model notebook |
| `prompts/prompt_library.md` | LLM prompt library |
| `data/sample_findings.csv` | Example input (10 rows, real check_ids/resource names, shape-matched to a Prowler export) |

## Using your real data

`data/sample_findings.csv` is a small hand-built sample covering all 8
tracked misconfigs plus 2 extra rows — it's for demonstrating the pipeline,
not your actual 192-finding scan. Replace it with your real ranked export
and re-run:

```bash
pip install nbformat   # if not already installed
python build_db.py --csv path/to/your_real_findings.csv --db db/consolidated_findings.db
python seed_catalogue.py
jupyter nbconvert --to notebook --execute --inplace notebooks/prioritization_model.ipynb
```

Your real CSV needs these columns (matches standard Prowler CSV output):
`finding_id, check_id, region, resource_id, resource_type, severity, status, misconfig_id, title`.
If your existing CSV has different column names, rename the header row —
the scoring logic doesn't care about anything else.

## Scoring model

`priority_score = severity_score x exposure_score x blast_radius`

All three weight tables live in `build_db.py` (`SEVERITY_WEIGHTS`,
`EXPOSURE_RULES`, `BLAST_RADIUS_BY_RESOURCE_TYPE`) — same logic as the
original Week 2 stdlib script, just persisting to SQLite instead of a flat
CSV so it satisfies the "consolidated findings database" deliverable.

## Database schema

Two tables:
- `findings` — every Prowler finding, scored and ranked
- `misconfig_catalogue` — the 8 tracked misconfigs (MC-01 to MC-08), their
  ISO 27001 Annex A control mapping, and remediation status

Joined on `misconfig_id`. Example query — top unremediated findings:

```sql
SELECT f.priority_rank, f.severity, f.misconfig_id, f.title
FROM findings f
JOIN misconfig_catalogue m ON f.misconfig_id = m.misconfig_id
WHERE f.status = 'FAIL' AND m.status != 'remediated'
ORDER BY f.priority_rank;
```

## Prompt library

`prompts/prompt_library.md` has the shared system prompt, the per-finding
template, and worked examples for all 8 tracked misconfigs — including the
`AUTO_SAFE` / `HUMAN_APPROVAL_REQUIRED` classification that determined
which findings went to the safe-remediation Lambdas vs. the approval queue.
