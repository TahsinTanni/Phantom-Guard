# Phantom Guard

Naming grammar and described malware mechanisms in GHSA/OSV malware
advisories for PyPI and npm.

**Status:** Analysis frozen at research_log.md §5.14 (2026-10-04).
Manuscript in preparation.

## Overview

**Research question.** Do malicious packages with compound or generic
names (built from tokens such as `py`, `tools`, `ai`, `client`, `utils`) more often have
advisories that describe a concrete malware mechanism than packages with
other names?

**Data.** A frozen snapshot of 401 malware advisory records for 200
packages (201 PyPI, 200 npm records), retrieved on 2026-10-02 from the
GitHub Security Advisories (200 records) and OSV.dev (201 records) APIs.
Advisories were published between 2025-10-30 and 2026-10-02.

**Method.** Each package name is classified by a token-based
compound/generic naming grammar (`src/data/naming_grammar.py`). Advisory
text is labeled by a regex taxonomy of malware mechanisms
(`src/labeling/malware_taxonomy.py`), with negated mentions removed.
Records are collapsed to independent campaigns, so that cross-source
re-reports of one package and multi-name campaigns by one actor count
once. A campaign is positive on either variable if any member is. The
association is tested with Fisher's exact test, Cochran–Mantel–Haenszel
tests stratified by ecosystem and by reporter count, and a logistic
regression adjusting for ecosystem and reporter coverage. The grammar flags
7/139 (5.0%) of a published set of LLM-hallucinated names against 18.5%
of top-5,000 benign names, so it is treated as a compound/generic naming
measure, not a hallucination detector.

**Headline result.** At the campaign level (n = 94), there is no
association: pooled OR 0.884 [95% CI 0.353, 2.211], p 0.818; CMH by
ecosystem OR 0.890, p 0.802; adjusted logistic OR 0.912 [0.331, 2.515],
p 0.858. Power to detect OR 2.0 at n = 94 is 0.31; 339 campaigns are
needed for 80% power. The estimate depends on reporter coverage. Using
GHSA advisory text alone gives OR 2.851, p 0.047. This is one of several
text-source and grouping settings that were examined, with no correction
for multiple comparisons, and the npm stratum has a zero cell. OSV
records combine more reporters' write-ups than GHSA records, and the
extra detail falls mostly on packages the grammar does not flag.

## Repository layout

```
run_check.py            Reproduces log Section 5.14 and the power analysis
review_diagnostics.py   Additional diagnostics on the frozen snapshot
config/base.yaml        Project config and data-source status flags
data/frozen/            incidents_snapshot.jsonl (401 records; read-only)
data/external/          Hallucinated-name list and benign top-N name lists
data/metadata/          Manifests for the snapshot and the benign lists
src/data/               GHSA/OSV and registry clients, naming grammar, seed lists
src/labeling/           Malware taxonomy (regex) and labeler
src/statistics/         Campaign collapse, Fisher/CMH, logistic models, power
src/evaluation/         Grammar validation, labeler spot check, signature diagnostics
src/utils/              Environment, manifests, checkpointing
tests/                  pytest suite
reports/                Research log, spot-check sheet, other reports
results/                JSON outputs of run_check.py and evaluation scripts
```

### Legacy modules

`src/labeling/injection_taxonomy.py` and `src/labeling/injection_labeler.py`
are retained for provenance and are not used in the analysis.

## Reproduction

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

- **Incident snapshot.** `data/frozen/incidents_snapshot.jsonl`, described
  by `data/metadata/incidents_snapshot_manifest.json`. 401 records, SHA-256
  `cb830db6232fd164faa16707da847133269b07b7194e168a4bc705a454ea4f52`.
  It has 200 records from the GHSA REST API (`type=malware`, ecosystems pip
  and npm) and 201 from OSV.dev per-package queries. The records cover
  200 packages (201 PyPI, 200 npm records). Fetched 2026-10-02
  20:00:31–20:01:14 UTC. Advisories were published between 2025-10-30
  and 2026-10-02. License: GHSA advisory data is CC-BY-4.0, and OSV
  records carry the license of their upstream source (OpenSSF
  malicious-packages: Apache-2.0). Per-record credits are kept in the
  advisory text.
- **Hallucinated names.** `data/external/hallucinated_names.txt`, 121
  PyPI + 18 npm names. Churilov, A. (2026), arXiv:2605.17062, release
  `v0.2-preprint` of github.com/churik5/slopsquatting-replication-2026
  (Zenodo DOI 10.5281/zenodo.19859120), retrieved 2026-10-03. License
  CC-BY-4.0. Details in `hallucinated_names_SOURCES.md`.
- **Benign name lists.** Fetched 2026-10-03. The manifests, with SHA-256
  checksums, are in `data/metadata/`:
  - `benign_top5000_pypi.txt`: top 5,000 from hugovk/top-pypi-packages
    (list dated 2026-10-01 12:40:51).
  - `benign_top5000_npm.txt`: top 5,000 from `npm-high-impact@1.13.0`
    (`lib/top.js` via jsDelivr).
  - `benign_npm_search_api.txt`: 2,593 names from the npm registry search
    API, used only as a sensitivity set.

## Analysis rules

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

## Citation

```bibtex
@unpublished{tanni2026phantomguard,
  title  = {Naming Grammar and Described Malware Mechanisms in
            {GHSA}/{OSV} Malware Advisories},
  author = {Tanni, Tahsin Tajwar and Khan, Nafiz},
  institution = {BRAC University},
  year   = {2026},
  note   = {Manuscript under preparation; preprint forthcoming.}
}
```

## License

Code is released under the MIT License (see `LICENSE`). Data files remain
under the license of their original source, as listed under Data
provenance and licenses.
