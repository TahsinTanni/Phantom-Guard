# Naming and described mechanisms in GHSA/OSV malware advisories

## What this is

A measurement study of confirmed-malicious PyPI and npm packages reported in
the GitHub Security Advisory database (GHSA) and OSV. Advisory records are
not independent observations: the same package is re-reported across the
two sources, and one attacker often publishes many names with one payload.
Records are therefore collapsed to independent campaigns before testing.
The outcome is whether the advisory text describes a malware mechanism
(regex taxonomy, validated by two annotators). That label depends strongly
on which analysts reported the package (reporter coverage). Compound/generic
package naming (e.g. `py-*`, `*-tools`) has no detectable association with
it.

## Main results (v2 corpus)

| | Value |
|---|---|
| Campaigns | 317 (npm 152, PyPI 165), from 994 advisory records |
| Grammar flag vs. described mechanism, pooled Fisher | OR 1.045 [0.635, 1.721], p = 0.899 |
| Adjusted (logit with ecosystem and reporter coverage) | OR 0.741 [0.424, 1.294], p = 0.292 |
| Power at OR 2.0 | 0.78 |
| Reporter coverage (Amazon Inspector, adjusted model) | OR 23.1 [8.5, 62.6] |
| Labeler precision | 55/60 = 0.917 [0.819, 0.964] |
| Labeler miss rate | 17/40 = 0.425 [0.285, 0.578] |
| Inter-annotator agreement (Cohen's κ) | 0.783 (precision sheet) / 0.658 (recall sheet) |

The v1 corpus (401 records, 105 campaigns) is kept for comparison; the
research log (`reports/research_log.md`, §5.18–5.19) has the v1-vs-v2
tables, the grouping history and the misclassification-corrected estimates.

## Repository layout

```
archive/      Superseded v0 draft of the analysis paper and its figures
config/       Project configuration (base.yaml)
data/         Frozen snapshots, manifests, validation name lists, recorded decisions
paper/        Analysis paper (main.tex) and its figure
paper_dib/    Data article (dib_main.tex) and its figures
reports/      Research log, collapse audits, annotation sheets, cleanup plan
results/      Outputs of run_check.py and the evaluation scripts (incl. figures/v2/)
src/          Collection, labeling, statistics, evaluation and figure code
tests/        pytest suite
run_check.py  One-command reproduction of the campaign-level analysis
review_diagnostics.py  Additional diagnostics on the frozen snapshot
CLAUDE.md     Analysis rules
```

## Setup

Python 3.14 (results produced with 3.14.6). No GPU, no credentials.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-lock.txt   # exact versions used for the results
# or: pip install -r requirements.txt  # minimum versions
```

## Reproduce

```bash
python -m pytest tests/ -q                # expect 187 passed
python run_check.py                       # v1 corpus
python run_check.py --snapshot v2         # v2 corpus (main results)
python run_check.py --snapshot v2 --text-source ghsa   # GHSA-text-only sensitivity
python -m src.evaluation.agreement        # labeler agreement, precision, miss rate
python -m src.evaluation.corpus_report    # assembles results/analysis_v2.json

cd paper && pdflatex main.tex && pdflatex main.tex && cd ..
cd paper_dib && pdflatex dib_main.tex && pdflatex dib_main.tex && cd ..
```

`run_check.py` reads only the frozen snapshots (no network) and writes to
`results/`. `corpus_report` reads the outputs of the commands before it.

## Analysis rules

See `CLAUDE.md`.

## Data

- `data/frozen/` holds the two frozen advisory snapshots:
  `incidents_snapshot.jsonl` (v1, 401 records) and
  `incidents_snapshot_v2.jsonl` (v2, 994 records). They must not be
  modified; new data goes in a new file with its own manifest.
- `data/metadata/` holds a manifest for each snapshot and each validation
  name list, with its SHA-256 checksum, record count, source and license.
- `data/external/` holds the hallucinated-name and benign name lists used to
  validate the naming grammar (provenance in `hallucinated_names_SOURCES.md`).
- `data/manual_merges.json` and `data/recall_categories_v2.json` record
  human decisions used by the sensitivity analysis and the labeler
  validation.

## License

Code: MIT License (see `LICENSE`). Data files keep the license of their
source, recorded in each manifest's `license` field (GHSA records CC BY 4.0;
OSV records per upstream source).
