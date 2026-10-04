# Phantom Guard — working rules

Research project: does naming grammar predict described malware mechanisms
in GHSA/OSV advisories. Read reports/review.md first — it lists the open
problems in priority order. reports/research_log.md is the history.

## Hard rules
- NEVER edit regex patterns in src/labeling/malware_taxonomy.py or token
  lists in src/data/naming_grammar.py to make a statistical result change.
  Pattern changes are allowed only when justified by a specific text example
  and must come with a regression test.
- NEVER modify data/frozen/incidents_snapshot.jsonl. New data goes in a new
  file with its own manifest.
- Every analysis change must keep `python run_check.py` reproducing
  Section 5.14 exactly (n 94, table [[13,12],[38,31]], OR 0.884, p 0.818
  on the "any source" setting; supersedes 5.13's OR 1.178, p 0.829 and
  5.6's OR 0.849, p 0.702), or explain in the log why it no longer should.
- After any change: run `python -m pytest tests/ -q` (expect 150+ passed).
- Append what you did and found to reports/research_log.md as a new
  numbered subsection. Report numbers, not adjectives.

## Environment
- .venv on Python 3.14; activate before running anything.
- No GPU, no secrets needed. GHSA API is unauthenticated (60 req/hr).