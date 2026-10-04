# Phantom Guard

## What this is

A study of whether package-naming grammar predicts the malware mechanisms
described in GitHub Security Advisory (GHSA) and OSV malware advisories for
PyPI and npm. The corpus is a frozen snapshot of 401 advisory records (200
packages), collapsed to independent campaigns so that re-reports of one
package and multi-name campaigns by one actor are counted once. The
independent variable is a compound/generic naming-grammar flag
(`src/data/naming_grammar.py`); the outcome is whether the advisory text
describes a concrete malware mechanism (`src/labeling/malware_taxonomy.py`).
The estimate depends on which reporters' text is used: OSV records carry
more reporters' write-ups than GHSA records, and that extra detail falls
mostly on unflagged packages (research log 5.9–5.10). On the default
setting the result is null: n 94 campaigns, OR 0.884, p 0.818, with power
0.31 to detect OR 2.0. The grammar flags 7/139 (5.0%) of a published set
of LLM-hallucinated names against 18.5% of top-5,000 benign names (log
5.11), so it is reported as compound/generic naming only, with no claim
about hallucination.

`reports/research_log.md` is the full history. `reports/review.md` lists
open problems in priority order.

## Repository layout

```
run_check.py            Reproduces log Section 5.14 and the power analysis
review_diagnostics.py   Diagnostics referenced in reports/review.md
config/base.yaml        Project config and data-source status flags
data/frozen/            incidents_snapshot.jsonl (401 records; read-only)
data/external/          Hallucinated-name list and benign top-N name lists
data/metadata/          Manifests for the benign lists
src/data/               GHSA/OSV and registry clients, naming grammar, seed lists
src/labeling/           Malware taxonomy (regex) and labeler
src/statistics/         Campaign collapse, Fisher/CMH, logistic models, power
src/evaluation/         Grammar validation, labeler spot check, signature diagnostics
src/utils/              Environment, manifests, checkpointing
tests/                  pytest suite
reports/                Research log, review, spot-check sheet, other reports
results/                JSON outputs of run_check.py and evaluation scripts
```

`src/labeling/injection_*.py` belong to an earlier framing (log 4.1) and
are not used in the analysis.

## How to reproduce

Python 3.14. No GPU and no credentials needed.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m pytest tests/ -q       # expect 158 passed
python run_check.py
```

`run_check.py` reads only the frozen snapshot (no network) and writes
`results/power_campaign_level.json`. Expected headline numbers (log 5.14,
text source "any", grouping "any"):

| Stratum | n | table | OR [95% CI] | p |
|---|---|---|---|---|
| Pooled (Fisher) | 94 | [[13,12],[38,31]] | 0.884 [0.353, 2.211] | 0.818 |
| npm | 22 | [[3,3],[5,11]] | 2.200 [0.323, 14.975] | 0.624 |
| PyPI | 72 | [[10,9],[33,20]] | 0.673 [0.234, 1.940] | 0.587 |
| CMH by ecosystem | 94 | — | 0.890 [0.355, 2.232] | 0.802 |

Power at n 94 for OR 2.0: 0.31; n for 80% power at OR 2.0: 339.
Other text/grouping settings: `python run_check.py --text-source ghsa`
(see `--help`). The GHSA-text setting gives OR 2.851, p 0.047; log 5.14
explains why that is not read as a finding.

## Data provenance and licenses

- **Incident snapshot** — `data/frozen/incidents_snapshot.jsonl`, 401
  records: 200 from the GHSA REST API (`type=malware`, ecosystems pip and
  npm) and 201 from OSV.dev per-package queries; 201 PyPI, 200 npm.
  Advisory `published_at` ranges from 2025-10-30 to 2026-10-02, so the
  pull was made on or after 2026-10-02. The file was committed on
  2026-10-04. The log (5.5) mentions a snapshot manifest; it is not in
  `data/metadata/`, and the exact pull date is not recorded. Advisory text
  is from GHSA (CC-BY-4.0) and OSV, which republishes the OpenSSF
  malicious-packages data (Apache-2.0); per-record credits are kept in
  the text.
- **Hallucinated names** — `data/external/hallucinated_names.txt`, 121
  PyPI + 18 npm names. Churilov, A. (2026), arXiv:2605.17062, release
  `v0.2-preprint` of github.com/churik5/slopsquatting-replication-2026
  (Zenodo DOI 10.5281/zenodo.19859120), retrieved 2026-10-03. License
  CC-BY-4.0. Details in `hallucinated_names_SOURCES.md`.
- **Benign name lists** — fetched 2026-10-03, manifests with SHA-256 in
  `data/metadata/`:
  - `benign_top5000_pypi.txt`: top 5,000 from hugovk/top-pypi-packages
    (list dated 2026-10-01 12:40:51; not version-pinned).
  - `benign_top5000_npm.txt`: top 5,000 from `npm-high-impact@1.13.0`
    (`lib/top.js` via jsDelivr).
  - `benign_npm_search_api.txt`: 2,593 names from the npm registry search
    API, live at fetch time.

## Contributing / analysis rules

1. Do not change the regex patterns in `src/labeling/malware_taxonomy.py`
   or the token lists in `src/data/naming_grammar.py` to move a
   statistical result. A pattern change needs a specific advisory-text
   example that justifies it and a regression test built on that text.
2. Do not modify `data/frozen/incidents_snapshot.jsonl`. New data goes in
   a new file with its own manifest.
3. Every analysis change must keep `python run_check.py` reproducing the
   current target (log 5.14: n 94, [[13,12],[38,31]], OR 0.884, p 0.818),
   or the research log must explain why the target changed. After any
   change, run `python -m pytest tests/ -q` and append a numbered
   subsection to `reports/research_log.md` that reports numbers.
