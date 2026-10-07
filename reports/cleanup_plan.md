# Repository cleanup plan (read-only proposal)

Status 2026-10-06, commit `e8a4cfa` (in sync with `origin/main`). Nothing has been moved, deleted or edited; this file is the only change. `data/frozen/` is untouched and classified KEEP.

## Summary

| Group | Tracked files | Size |
|---|---|---|
| KEEP | 132 | 4.81 MB |
| SUPERSEDED | 34 | 1.29 MB |
| UNSURE | 2 | 758.4 KB |
| **Total tracked** | **168** | **6.84 MB** |

- **SUPERSEDED, proposed for removal from the tracked tree:** 34 files, 1.29 MB.
  - archive: 5 files, 791.1 KB;
  - delete: 29 files, 529.0 KB. Of these, 26 are empty placeholders.
- **UNSURE:** the two compiled PDFs (758 KB). They are rebuildable, but you decide whether they stay tracked.
- **GENERATED, local only and already gitignored:** caches, LaTeX build files and `.DS_Store`, about 1.5 MB, plus `.venv/` at 392 MB. Nothing generated is tracked in git.
- **Saved in the tracked tree:** 0.53 MB from the deletions. The 0.79 MB moved to `archive/` stays tracked. Dropping the two PDFs as well would save about 1.3 MB in total. The local clean-up (caches, build files, `.DS_Store`) frees about 1.5 MB.

## Checks

- **References (step 3).** Every removal candidate was grepped across code, tests, the research log, both papers and the README, excluding `.git`, `.venv` and `notes/`.
  - Files with any reference were moved to KEEP. Examples: `reports/review.md`, `review_diagnostics.py`, `reports/annotation_guidelines.md`, `reports/phase0_go_no_go.md`, `config/base.yaml`, `data/raw`, `data/processed`, and all `results/*` files.
  - Four v0 figures are referenced, but only by `paper/main_old.tex`, which is itself superseded. They are archived together with it, so the reference stays intact.
- **Dependencies (step 4).** A copy of the repo without every SUPERSEDED file (and without caches, build files and `notes/`) was built in a scratch directory.
  - The suite gives **187 passed**.
  - `python run_check.py` gives 105 campaigns and OR 0.812; `python run_check.py --snapshot v2` gives 317 campaigns and OR 1.045.
  - Both result JSONs are byte-identical to the ones in the repo. `run_check.py` and the tests read only KEEP files.
  - No module imports `src.features`, `src.models` or `src.training`.
- **Gaps.** There is no `CLAUDE.md` and no lock file. `requirements.txt` gives minimum versions only. Optional: `.venv/bin/pip freeze > requirements-lock.txt`.

## Proposed `.gitignore`

```gitignore
# Python
__pycache__/
*.py[cod]
.pytest_cache/
.venv/

# OS / editors
.DS_Store
.vscode/
.idea/

# LaTeX build files (any folder)
*.aux
*.log
*.out
*.spl
*.bbl
*.blg
*.toc
*.fls
*.fdb_latexmk
*.synctex.gz

# Compiled papers: uncomment if you decide not to track them (UNSURE below)
# paper/main.pdf
# paper_dib/dib_main.pdf

# Private notes (paper outline) — must stay out of the repo
notes/
```

The current file lists the LaTeX patterns only for `paper/` and `paper_dib/`. The proposal covers every folder, plus `.bbl`, `.blg`, `.synctex.gz` and the other LaTeX intermediates.

## Proposed layout

Only removals and one archive folder are needed. `src/`, `tests/`, `data/frozen/`, `results/` and `reports/` stay where they are.

```text
.
├── README.md, LICENSE, requirements.txt, pytest.ini, run_check.py, review_diagnostics.py
├── config/base.yaml
├── data/
│   ├── frozen/            (v1 + v2 snapshots — untouched)
│   ├── metadata/          (manifests / checksums)
│   ├── external/          (validation name lists)
│   ├── raw/, processed/   (empty; used by src/utils path helpers)
│   ├── manual_merges.json, recall_categories_v2.json
├── src/  (data, evaluation, labeling, statistics, utils, visualization)
├── tests/
├── results/  (+ figures/v2/)
├── reports/  (research log, audits, annotation sheets)
├── paper/  (main.tex, figures/)        paper_dib/  (dib_main.tex, figures/)
└── archive/paper_v0/  (main_old.tex + the 4 figures it uses)
```

**Removed folders:** `data/interim/`, `experiments/`, `notebooks/`, `results/metrics/`, `results/statistical_tests/`, `results/tables/`, `src/features/`, `src/models/`, `src/training/`, and `paper/PhantomGuard/` (emptied by the archive and delete steps).

**Optional, not proposed:** moving `review_diagnostics.py` to `scripts/`. It would also need the path updated in `README.md` and `reports/review.md`, so it is left in place.

## Archive vs delete

- **Archive** (`archive/paper_v0/`): `paper/main_old.tex` and the four v0 figures it includes. These are the record of the first draft, and the draft stays compilable.
- **Delete:**
  - the three unreferenced v0 diagram drafts (`fig_methodology.pdf`, `image.png`, `screen.png`);
  - the 14 unused scaffold files;
  - the 12 redundant `.gitkeep` placeholders.
- Everything deleted stays recoverable from git history. Suggested first step when you apply the plan: `git tag pre-cleanup`.

## File table

| Path | Size | Group | Reason | Referenced by | Action |
|---|---|---|---|---|---|
| `config/.gitkeep` | 0.0 KB | SUPERSEDED | Placeholder for an empty folder; the folder now has real files (and __init__.py for packages) | none | delete |
| `data/external/.gitkeep` | 0.0 KB | SUPERSEDED | Placeholder for an empty folder; the folder now has real files (and __init__.py for packages) | none | delete |
| `data/interim/.gitkeep` | 0.0 KB | SUPERSEDED | Empty Phase-0 scaffold folder, never used; replaced by the layout actually in use (data/frozen, data/metadata, results/, src/evaluation, src/statistics) | none (grep: no path or import references; 'notebooks' appears only as a generic word) | delete |
| `data/metadata/.gitkeep` | 0.0 KB | SUPERSEDED | Placeholder for an empty folder; the folder now has real files (and __init__.py for packages) | none | delete |
| `experiments/checkpoints/.gitkeep` | 0.0 KB | SUPERSEDED | Empty Phase-0 scaffold folder, never used; replaced by the layout actually in use (data/frozen, data/metadata, results/, src/evaluation, src/statistics) | none (grep: no path or import references; 'notebooks' appears only as a generic word) | delete |
| `experiments/configs/.gitkeep` | 0.0 KB | SUPERSEDED | Empty Phase-0 scaffold folder, never used; replaced by the layout actually in use (data/frozen, data/metadata, results/, src/evaluation, src/statistics) | none (grep: no path or import references; 'notebooks' appears only as a generic word) | delete |
| `experiments/runs/.gitkeep` | 0.0 KB | SUPERSEDED | Empty Phase-0 scaffold folder, never used; replaced by the layout actually in use (data/frozen, data/metadata, results/, src/evaluation, src/statistics) | none (grep: no path or import references; 'notebooks' appears only as a generic word) | delete |
| `notebooks/.gitkeep` | 0.0 KB | SUPERSEDED | Empty Phase-0 scaffold folder, never used; replaced by the layout actually in use (data/frozen, data/metadata, results/, src/evaluation, src/statistics) | none (grep: no path or import references; 'notebooks' appears only as a generic word) | delete |
| `paper/PhantomGuard/prism-uploads/fig_correction_impact.pdf` | 24.1 KB | SUPERSEDED | Figure of the v0 draft (142-campaign numbers) | paper/main_old.tex only (itself superseded) — replaced by paper/figures/ and results/figures/v2/ | archive with main_old.tex (keeps the v0 draft compilable) |
| `paper/PhantomGuard/prism-uploads/fig_malware_categories.pdf` | 26.0 KB | SUPERSEDED | Figure of the v0 draft (142-campaign numbers) | paper/main_old.tex only (itself superseded) — replaced by paper/figures/ and results/figures/v2/ | archive with main_old.tex (keeps the v0 draft compilable) |
| `paper/PhantomGuard/prism-uploads/fig_methodology.pdf` | 26.8 KB | SUPERSEDED | Early pipeline-diagram drafts (401 records → 142 campaigns, npm OR 178) | none — replaced by the TikZ Fig. 1 in paper/main.tex | delete |
| `paper/PhantomGuard/prism-uploads/fig_odds_ratios.pdf` | 24.3 KB | SUPERSEDED | Figure of the v0 draft (142-campaign numbers) | paper/main_old.tex only (itself superseded) — replaced by paper/figures/ and results/figures/v2/ | archive with main_old.tex (keeps the v0 draft compilable) |
| `paper/PhantomGuard/prism-uploads/image.png` | 235.8 KB | SUPERSEDED | Early pipeline-diagram drafts (401 records → 142 campaigns, npm OR 178) | none — replaced by the TikZ Fig. 1 in paper/main.tex | delete |
| `paper/PhantomGuard/prism-uploads/screen.png` | 266.4 KB | SUPERSEDED | Early pipeline-diagram drafts (401 records → 142 campaigns, npm OR 178) | none — replaced by the TikZ Fig. 1 in paper/main.tex | delete |
| `paper/PhantomGuard/prism-uploads/screen_2.png` | 681.7 KB | SUPERSEDED | Figure of the v0 draft (142-campaign numbers) | paper/main_old.tex only (itself superseded) — replaced by paper/figures/ and results/figures/v2/ | archive with main_old.tex (keeps the v0 draft compilable) |
| `paper/main_old.tex` | 35.0 KB | SUPERSEDED | First (v0, 142-campaign) draft of the analysis paper | none — replaced by paper/main.tex | archive (archive/paper_v0/) |
| `reports/.gitkeep` | 0.0 KB | SUPERSEDED | Placeholder for an empty folder; the folder now has real files (and __init__.py for packages) | none | delete |
| `results/figures/.gitkeep` | 0.0 KB | SUPERSEDED | Placeholder for an empty folder; the folder now has real files (and __init__.py for packages) | none | delete |
| `results/metrics/.gitkeep` | 0.0 KB | SUPERSEDED | Empty Phase-0 scaffold folder, never used; replaced by the layout actually in use (data/frozen, data/metadata, results/, src/evaluation, src/statistics) | none (grep: no path or import references; 'notebooks' appears only as a generic word) | delete |
| `results/statistical_tests/.gitkeep` | 0.0 KB | SUPERSEDED | Empty Phase-0 scaffold folder, never used; replaced by the layout actually in use (data/frozen, data/metadata, results/, src/evaluation, src/statistics) | none (grep: no path or import references; 'notebooks' appears only as a generic word) | delete |
| `results/tables/.gitkeep` | 0.0 KB | SUPERSEDED | Empty Phase-0 scaffold folder, never used; replaced by the layout actually in use (data/frozen, data/metadata, results/, src/evaluation, src/statistics) | none (grep: no path or import references; 'notebooks' appears only as a generic word) | delete |
| `src/data/.gitkeep` | 0.0 KB | SUPERSEDED | Placeholder for an empty folder; the folder now has real files (and __init__.py for packages) | none | delete |
| `src/evaluation/.gitkeep` | 0.0 KB | SUPERSEDED | Placeholder for an empty folder; the folder now has real files (and __init__.py for packages) | none | delete |
| `src/features/.gitkeep` | 0.0 KB | SUPERSEDED | Empty Phase-0 scaffold folder, never used; replaced by the layout actually in use (data/frozen, data/metadata, results/, src/evaluation, src/statistics) | none (grep: no path or import references; 'notebooks' appears only as a generic word) | delete |
| `src/features/__init__.py` | 0.0 KB | SUPERSEDED | Empty Phase-0 scaffold folder, never used; replaced by the layout actually in use (data/frozen, data/metadata, results/, src/evaluation, src/statistics) | none (grep: no path or import references; 'notebooks' appears only as a generic word) | delete |
| `src/labeling/.gitkeep` | 0.0 KB | SUPERSEDED | Placeholder for an empty folder; the folder now has real files (and __init__.py for packages) | none | delete |
| `src/models/.gitkeep` | 0.0 KB | SUPERSEDED | Empty Phase-0 scaffold folder, never used; replaced by the layout actually in use (data/frozen, data/metadata, results/, src/evaluation, src/statistics) | none (grep: no path or import references; 'notebooks' appears only as a generic word) | delete |
| `src/models/__init__.py` | 0.0 KB | SUPERSEDED | Empty Phase-0 scaffold folder, never used; replaced by the layout actually in use (data/frozen, data/metadata, results/, src/evaluation, src/statistics) | none (grep: no path or import references; 'notebooks' appears only as a generic word) | delete |
| `src/statistics/.gitkeep` | 0.0 KB | SUPERSEDED | Placeholder for an empty folder; the folder now has real files (and __init__.py for packages) | none | delete |
| `src/training/.gitkeep` | 0.0 KB | SUPERSEDED | Empty Phase-0 scaffold folder, never used; replaced by the layout actually in use (data/frozen, data/metadata, results/, src/evaluation, src/statistics) | none (grep: no path or import references; 'notebooks' appears only as a generic word) | delete |
| `src/training/__init__.py` | 0.0 KB | SUPERSEDED | Empty Phase-0 scaffold folder, never used; replaced by the layout actually in use (data/frozen, data/metadata, results/, src/evaluation, src/statistics) | none (grep: no path or import references; 'notebooks' appears only as a generic word) | delete |
| `src/utils/.gitkeep` | 0.0 KB | SUPERSEDED | Placeholder for an empty folder; the folder now has real files (and __init__.py for packages) | none | delete |
| `src/visualization/.gitkeep` | 0.0 KB | SUPERSEDED | Placeholder for an empty folder; the folder now has real files (and __init__.py for packages) | none | delete |
| `tests/.gitkeep` | 0.0 KB | SUPERSEDED | Placeholder for an empty folder; the folder now has real files (and __init__.py for packages) | none | delete |
| `paper/main.pdf` | 248.0 KB | UNSURE | Rebuildable (`pdflatex` ×2 in paper/ or paper_dib/), but the compiled PDF is what most visitors open; Zenodo/reviewers may expect it | none (no file references the PDF) | your call: keep tracked, or ignore and attach to releases |
| `paper_dib/dib_main.pdf` | 510.4 KB | UNSURE | Rebuildable (`pdflatex` ×2 in paper/ or paper_dib/), but the compiled PDF is what most visitors open; Zenodo/reviewers may expect it | none (no file references the PDF) | your call: keep tracked, or ignore and attach to releases |
| `.gitignore` | 0.2 KB | KEEP | Repository metadata (to be replaced by the proposed .gitignore) | — | keep |
| `LICENSE` | 1.1 KB | KEEP | Repository metadata | — | keep |
| `README.md` | 7.1 KB | KEEP | Repository metadata | — | keep |
| `config/base.yaml` | 1.7 KB | KEEP | Code, tests or configuration needed to reproduce the results | run_check.py / test suite / README | keep |
| `data/external/benign_npm_search_api.txt` | 54.0 KB | KEEP | Cached validation name lists (grammar validation, Table I) | src/evaluation/grammar_validation.py, tests/test_grammar_validation.py, research log, README | keep |
| `data/external/benign_top5000_npm.txt` | 84.6 KB | KEEP | Cached validation name lists (grammar validation, Table I) | src/evaluation/grammar_validation.py, tests/test_grammar_validation.py, research log, README | keep |
| `data/external/benign_top5000_pypi.txt` | 67.7 KB | KEEP | Cached validation name lists (grammar validation, Table I) | src/evaluation/grammar_validation.py, tests/test_grammar_validation.py, research log, README | keep |
| `data/external/hallucinated_names.txt` | 2.4 KB | KEEP | Cached validation name lists (grammar validation, Table I) | src/evaluation/grammar_validation.py, tests/test_grammar_validation.py, research log, README | keep |
| `data/external/hallucinated_names_SOURCES.md` | 0.9 KB | KEEP | Cached validation name lists (grammar validation, Table I) | src/evaluation/grammar_validation.py, tests/test_grammar_validation.py, research log, README | keep |
| `data/frozen/incidents_snapshot.jsonl` | 747.5 KB | KEEP | Frozen snapshot — never touch | run_check.py, tests, both papers, research log | keep |
| `data/frozen/incidents_snapshot_v2.jsonl` | 1.73 MB | KEEP | Frozen snapshot — never touch | run_check.py, tests, both papers, research log | keep |
| `data/manual_merges.json` | 1.1 KB | KEEP | Recorded human decisions used by the analysis | run_check.py / src/evaluation/agreement.py, tests, research log | keep |
| `data/metadata/benign_npm_search_api.manifest.json` | 0.8 KB | KEEP | Manifest / SHA-256 checksum | research log, DIB article | keep |
| `data/metadata/benign_top5000_npm.manifest.json` | 0.6 KB | KEEP | Manifest / SHA-256 checksum | research log, DIB article | keep |
| `data/metadata/benign_top5000_pypi.manifest.json` | 0.7 KB | KEEP | Manifest / SHA-256 checksum | research log, DIB article | keep |
| `data/metadata/incidents_snapshot_manifest.json` | 1.3 KB | KEEP | Manifest / SHA-256 checksum | research log, DIB article | keep |
| `data/metadata/incidents_snapshot_v2.manifest.json` | 1.3 KB | KEEP | Manifest / SHA-256 checksum | research log, DIB article | keep |
| `data/processed/.gitkeep` | 0.0 KB | KEEP | Folders created/used by the path helpers | src/utils/environment.py, src/utils/manifest.py, tests/test_environment.py | keep |
| `data/raw/.gitkeep` | 0.0 KB | KEEP | Folders created/used by the path helpers | src/utils/environment.py, src/utils/manifest.py, tests/test_environment.py | keep |
| `data/recall_categories_v2.json` | 3.6 KB | KEEP | Recorded human decisions used by the analysis | run_check.py / src/evaluation/agreement.py, tests, research log | keep |
| `paper/figures/fig_dv_by_reporter.pdf` | 49.6 KB | KEEP | Paper source or a figure it includes (byte-identical to results/figures/v2/fig_dv_by_reporter.pdf, but the paper needs its own copy) | paper/main.tex | keep |
| `paper/main.tex` | 25.3 KB | KEEP | Paper source or a figure it includes | paper/main.tex | keep |
| `paper_dib/dib_main.tex` | 28.1 KB | KEEP | Paper source or a figure it includes | paper_dib/dib_main.tex | keep |
| `paper_dib/figures/fig_dv_by_reporter.pdf` | 49.6 KB | KEEP | Paper source or a figure it includes | paper_dib/dib_main.tex | keep |
| `paper_dib/figures/fig_grammar.pdf` | 30.9 KB | KEEP | Paper source or a figure it includes | paper_dib/dib_main.tex | keep |
| `paper_dib/figures/fig_mechanisms.pdf` | 31.3 KB | KEEP | Paper source or a figure it includes | paper_dib/dib_main.tex | keep |
| `paper_dib/figures/fig_reporters.pdf` | 41.5 KB | KEEP | Paper source or a figure it includes | paper_dib/dib_main.tex | keep |
| `paper_dib/figures/fig_timeline.pdf` | 29.2 KB | KEEP | Paper source or a figure it includes | paper_dib/dib_main.tex | keep |
| `paper_dib/figures/fig_units.pdf` | 43.4 KB | KEEP | Paper source or a figure it includes | paper_dib/dib_main.tex | keep |
| `pytest.ini` | 0.4 KB | KEEP | Code, tests or configuration needed to reproduce the results | run_check.py / test suite / README | keep |
| `reports/annotation_guidelines.md` | 4.0 KB | KEEP | Report / annotation sheet cited in the analysis | research log | keep |
| `reports/annotation_precision_v2.md` | 86.8 KB | KEEP | Report / annotation sheet cited in the analysis | research log 5.18–5.19, src/evaluation/agreement.py, tests/test_agreement.py | keep |
| `reports/annotation_precision_v2_annotator2.md` | 80.2 KB | KEEP | Report / annotation sheet cited in the analysis | research log 5.18–5.19, src/evaluation/agreement.py, tests/test_agreement.py | keep |
| `reports/annotation_recall_v2.md` | 89.9 KB | KEEP | Report / annotation sheet cited in the analysis | research log 5.18–5.19, src/evaluation/agreement.py, tests/test_agreement.py | keep |
| `reports/annotation_recall_v2_annotator2.md` | 84.5 KB | KEEP | Report / annotation sheet cited in the analysis | research log 5.18–5.19, src/evaluation/agreement.py, tests/test_agreement.py | keep |
| `reports/collapse_audit_v1.md` | 6.3 KB | KEEP | Report / annotation sheet cited in the analysis | research log 5.17–5.18 | keep |
| `reports/collapse_audit_v2.md` | 21.2 KB | KEEP | Report / annotation sheet cited in the analysis | research log 5.17–5.18 | keep |
| `reports/labeler_spot_check.md` | 54.0 KB | KEEP | Report / annotation sheet cited in the analysis | tests, src/evaluation/*, research log, DIB article | keep |
| `reports/osv_only_positives.md` | 14.0 KB | KEEP | Report / annotation sheet cited in the analysis | tests, src/evaluation/labeler_spot_check.py, research log, DIB article | keep |
| `reports/phase0_go_no_go.md` | 2.4 KB | KEEP | Report / annotation sheet cited in the analysis | research log, src/statistics/phase0_gate.py | keep |
| `reports/research_log.md` | 122.9 KB | KEEP | Report / annotation sheet cited in the analysis | README, both papers (methods history) | keep |
| `reports/review.md` | 12.1 KB | KEEP | Report / annotation sheet cited in the analysis | research log, run_check.py, src/, tests | keep |
| `requirements.txt` | 1.1 KB | KEEP | Code, tests or configuration needed to reproduce the results | run_check.py / test suite / README | keep |
| `results/agreement_v2.json` | 6.5 KB | KEEP | Result file cited in the log or papers (rebuildable, but kept as the record) | research log / papers / src (written by run_check.py, agreement.py or corpus_report.py) | keep |
| `results/analysis_v2.json` | 34.2 KB | KEEP | Result file cited in the log or papers (rebuildable, but kept as the record) | research log / papers / src (written by run_check.py, agreement.py or corpus_report.py) | keep |
| `results/annotation_sample_v2.json` | 29.7 KB | KEEP | Result file cited in the log or papers (rebuildable, but kept as the record) | research log / papers / src (written by run_check.py, agreement.py or corpus_report.py) | keep |
| `results/campaigns.csv` | 6.9 KB | KEEP | Result file cited in the log or papers (rebuildable, but kept as the record) | research log / papers / src (written by run_check.py, agreement.py or corpus_report.py) | keep |
| `results/campaigns__text-any__group-ghsa.csv` | 6.9 KB | KEEP | Result file cited in the log or papers (rebuildable, but kept as the record) | research log 5.18 (kept by decision of 2026-10-06); written by run_check.py | keep |
| `results/campaigns__text-any__group-osv.csv` | 6.8 KB | KEEP | Result file cited in the log or papers (rebuildable, but kept as the record) | research log 5.18 (kept by decision of 2026-10-06); written by run_check.py | keep |
| `results/campaigns__text-ghsa__group-any.csv` | 6.9 KB | KEEP | Result file cited in the log or papers (rebuildable, but kept as the record) | research log 5.18 (kept by decision of 2026-10-06); written by run_check.py | keep |
| `results/campaigns__text-ghsa__group-any__v2.csv` | 19.1 KB | KEEP | Result file cited in the log or papers (rebuildable, but kept as the record) | research log / papers / src (written by run_check.py, agreement.py or corpus_report.py) | keep |
| `results/campaigns__text-ghsa__group-ghsa.csv` | 6.9 KB | KEEP | Result file cited in the log or papers (rebuildable, but kept as the record) | research log 5.18 (kept by decision of 2026-10-06); written by run_check.py | keep |
| `results/campaigns__text-ghsa__group-osv.csv` | 6.8 KB | KEEP | Result file cited in the log or papers (rebuildable, but kept as the record) | research log 5.18 (kept by decision of 2026-10-06); written by run_check.py | keep |
| `results/campaigns__text-osv__group-any.csv` | 6.9 KB | KEEP | Result file cited in the log or papers (rebuildable, but kept as the record) | research log 5.18 (kept by decision of 2026-10-06); written by run_check.py | keep |
| `results/campaigns__text-osv__group-ghsa.csv` | 6.9 KB | KEEP | Result file cited in the log or papers (rebuildable, but kept as the record) | research log 5.18 (kept by decision of 2026-10-06); written by run_check.py | keep |
| `results/campaigns__text-osv__group-osv.csv` | 6.8 KB | KEEP | Result file cited in the log or papers (rebuildable, but kept as the record) | research log 5.18 (kept by decision of 2026-10-06); written by run_check.py | keep |
| `results/campaigns__v2.csv` | 19.1 KB | KEEP | Result file cited in the log or papers (rebuildable, but kept as the record) | research log / papers / src (written by run_check.py, agreement.py or corpus_report.py) | keep |
| `results/figures/v2/fig_dv_by_reporter.pdf` | 49.6 KB | KEEP | Result file cited in the log or papers (rebuildable, but kept as the record) | research log 5.19; written by `python -m src.visualization.paper_figures --snapshot v2` | keep |
| `results/figures/v2/fig_forest.pdf` | 39.0 KB | KEEP | Result file cited in the log or papers (rebuildable, but kept as the record) | research log 5.19; written by `python -m src.visualization.paper_figures --snapshot v2` | keep |
| `results/figures/v2/fig_grammar.pdf` | 30.9 KB | KEEP | Result file cited in the log or papers (rebuildable, but kept as the record) | research log 5.19; written by `python -m src.visualization.paper_figures --snapshot v2` | keep |
| `results/figures/v2/fig_mechanisms.pdf` | 31.4 KB | KEEP | Result file cited in the log or papers (rebuildable, but kept as the record) | research log 5.19; written by `python -m src.visualization.paper_figures --snapshot v2` | keep |
| `results/figures/v2/fig_power.pdf` | 29.4 KB | KEEP | Result file cited in the log or papers (rebuildable, but kept as the record) | research log 5.19; written by `python -m src.visualization.paper_figures --snapshot v2` | keep |
| `results/figures/v2/fig_reporters.pdf` | 43.1 KB | KEEP | Result file cited in the log or papers (rebuildable, but kept as the record) | research log 5.19; written by `python -m src.visualization.paper_figures --snapshot v2` | keep |
| `results/figures/v2/fig_timeline.pdf` | 32.3 KB | KEEP | Result file cited in the log or papers (rebuildable, but kept as the record) | research log 5.19; written by `python -m src.visualization.paper_figures --snapshot v2` | keep |
| `results/figures/v2/fig_units.pdf` | 48.5 KB | KEEP | Result file cited in the log or papers (rebuildable, but kept as the record) | research log 5.19; written by `python -m src.visualization.paper_figures --snapshot v2` | keep |
| `results/grammar_validation.json` | 14.0 KB | KEEP | Result file cited in the log or papers (rebuildable, but kept as the record) | research log / papers / src (written by run_check.py, agreement.py or corpus_report.py) | keep |
| `results/labeler_agreement_v2.json` | 28.0 KB | KEEP | Result file cited in the log or papers (rebuildable, but kept as the record) | research log / papers / src (written by run_check.py, agreement.py or corpus_report.py) | keep |
| `results/power_campaign_level.json` | 24.3 KB | KEEP | Result file cited in the log or papers (rebuildable, but kept as the record) | research log / papers / src (written by run_check.py, agreement.py or corpus_report.py) | keep |
| `results/power_campaign_level__text-any__group-ghsa.json` | 24.3 KB | KEEP | Result file cited in the log or papers (rebuildable, but kept as the record) | research log / papers / src (written by run_check.py, agreement.py or corpus_report.py) | keep |
| `results/power_campaign_level__text-any__group-osv.json` | 24.2 KB | KEEP | Result file cited in the log or papers (rebuildable, but kept as the record) | research log / papers / src (written by run_check.py, agreement.py or corpus_report.py) | keep |
| `results/power_campaign_level__text-ghsa__group-any.json` | 24.0 KB | KEEP | Result file cited in the log or papers (rebuildable, but kept as the record) | research log / papers / src (written by run_check.py, agreement.py or corpus_report.py) | keep |
| `results/power_campaign_level__text-ghsa__group-any__v2.json` | 24.4 KB | KEEP | Result file cited in the log or papers (rebuildable, but kept as the record) | research log / papers / src (written by run_check.py, agreement.py or corpus_report.py) | keep |
| `results/power_campaign_level__text-ghsa__group-ghsa.json` | 24.0 KB | KEEP | Result file cited in the log or papers (rebuildable, but kept as the record) | research log / papers / src (written by run_check.py, agreement.py or corpus_report.py) | keep |
| `results/power_campaign_level__text-ghsa__group-osv.json` | 24.1 KB | KEEP | Result file cited in the log or papers (rebuildable, but kept as the record) | research log / papers / src (written by run_check.py, agreement.py or corpus_report.py) | keep |
| `results/power_campaign_level__text-osv__group-any.json` | 24.3 KB | KEEP | Result file cited in the log or papers (rebuildable, but kept as the record) | research log / papers / src (written by run_check.py, agreement.py or corpus_report.py) | keep |
| `results/power_campaign_level__text-osv__group-ghsa.json` | 24.3 KB | KEEP | Result file cited in the log or papers (rebuildable, but kept as the record) | research log / papers / src (written by run_check.py, agreement.py or corpus_report.py) | keep |
| `results/power_campaign_level__text-osv__group-osv.json` | 24.2 KB | KEEP | Result file cited in the log or papers (rebuildable, but kept as the record) | research log / papers / src (written by run_check.py, agreement.py or corpus_report.py) | keep |
| `results/power_campaign_level__v2.json` | 24.4 KB | KEEP | Result file cited in the log or papers (rebuildable, but kept as the record) | research log / papers / src (written by run_check.py, agreement.py or corpus_report.py) | keep |
| `results/spot_check_sample.json` | 17.5 KB | KEEP | Result file cited in the log or papers (rebuildable, but kept as the record) | research log / papers / src (written by run_check.py, agreement.py or corpus_report.py) | keep |
| `results/spot_check_verdicts.json` | 49.4 KB | KEEP | Result file cited in the log or papers (rebuildable, but kept as the record) | research log / papers / src (written by run_check.py, agreement.py or corpus_report.py) | keep |
| `review_diagnostics.py` | 6.4 KB | KEEP | Diagnostics script for the review responses | README.md, reports/review.md | keep |
| `run_check.py` | 14.5 KB | KEEP | Code, tests or configuration needed to reproduce the results | run_check.py / test suite / README | keep |
| `src/__init__.py` | 0.0 KB | KEEP | Code, tests or configuration needed to reproduce the results | run_check.py / test suite / README | keep |
| `src/data/__init__.py` | 0.0 KB | KEEP | Code, tests or configuration needed to reproduce the results | run_check.py / test suite / README | keep |
| `src/data/build_snapshot.py` | 4.3 KB | KEEP | Code, tests or configuration needed to reproduce the results | run_check.py / test suite / README | keep |
| `src/data/collect_incidents.py` | 4.3 KB | KEEP | Code, tests or configuration needed to reproduce the results | run_check.py / test suite / README | keep |
| `src/data/collect_packages.py` | 6.5 KB | KEEP | Code, tests or configuration needed to reproduce the results | run_check.py / test suite / README | keep |
| `src/data/incident_clients.py` | 15.7 KB | KEEP | Code, tests or configuration needed to reproduce the results | run_check.py / test suite / README | keep |
| `src/data/leakage_checks.py` | 11.3 KB | KEEP | Code, tests or configuration needed to reproduce the results | run_check.py / test suite / README | keep |
| `src/data/naming_grammar.py` | 7.7 KB | KEEP | Code, tests or configuration needed to reproduce the results | run_check.py / test suite / README | keep |
| `src/data/registry_clients.py` | 8.0 KB | KEEP | Code, tests or configuration needed to reproduce the results | run_check.py / test suite / README | keep |
| `src/data/seed_lists.py` | 4.3 KB | KEEP | Code, tests or configuration needed to reproduce the results | run_check.py / test suite / README | keep |
| `src/evaluation/__init__.py` | 0.0 KB | KEEP | Code, tests or configuration needed to reproduce the results | run_check.py / test suite / README | keep |
| `src/evaluation/agreement.py` | 22.3 KB | KEEP | Code, tests or configuration needed to reproduce the results | run_check.py / test suite / README | keep |
| `src/evaluation/annotation_sheets.py` | 12.6 KB | KEEP | Code, tests or configuration needed to reproduce the results | run_check.py / test suite / README | keep |
| `src/evaluation/collapse_audit.py` | 9.2 KB | KEEP | Code, tests or configuration needed to reproduce the results | run_check.py / test suite / README | keep |
| `src/evaluation/corpus_report.py` | 8.5 KB | KEEP | Code, tests or configuration needed to reproduce the results | run_check.py / test suite / README | keep |
| `src/evaluation/grammar_validation.py` | 11.5 KB | KEEP | Code, tests or configuration needed to reproduce the results | run_check.py / test suite / README | keep |
| `src/evaluation/labeler_spot_check.py` | 13.0 KB | KEEP | Code, tests or configuration needed to reproduce the results | run_check.py / test suite / README | keep |
| `src/evaluation/signature_diagnostics.py` | 6.4 KB | KEEP | Code, tests or configuration needed to reproduce the results | run_check.py / test suite / README | keep |
| `src/labeling/__init__.py` | 0.0 KB | KEEP | Code, tests or configuration needed to reproduce the results | run_check.py / test suite / README | keep |
| `src/labeling/injection_labeler.py` | 5.1 KB | KEEP | Code, tests or configuration needed to reproduce the results | run_check.py / test suite / README | keep |
| `src/labeling/injection_taxonomy.py` | 12.5 KB | KEEP | Code, tests or configuration needed to reproduce the results | run_check.py / test suite / README | keep |
| `src/labeling/malware_labeler.py` | 5.5 KB | KEEP | Code, tests or configuration needed to reproduce the results | run_check.py / test suite / README | keep |
| `src/labeling/malware_taxonomy.py` | 10.9 KB | KEEP | Code, tests or configuration needed to reproduce the results | run_check.py / test suite / README | keep |
| `src/statistics/__init__.py` | 0.0 KB | KEEP | Code, tests or configuration needed to reproduce the results | run_check.py / test suite / README | keep |
| `src/statistics/h1_pilot_analysis.py` | 33.9 KB | KEEP | Code, tests or configuration needed to reproduce the results | run_check.py / test suite / README | keep |
| `src/statistics/misclassification.py` | 4.0 KB | KEEP | Code, tests or configuration needed to reproduce the results | run_check.py / test suite / README | keep |
| `src/statistics/phase0_gate.py` | 7.9 KB | KEEP | Code, tests or configuration needed to reproduce the results | run_check.py / test suite / README | keep |
| `src/statistics/power_analysis.py` | 8.7 KB | KEEP | Code, tests or configuration needed to reproduce the results | run_check.py / test suite / README | keep |
| `src/utils/__init__.py` | 0.0 KB | KEEP | Code, tests or configuration needed to reproduce the results | run_check.py / test suite / README | keep |
| `src/utils/checkpointing.py` | 5.8 KB | KEEP | Code, tests or configuration needed to reproduce the results | run_check.py / test suite / README | keep |
| `src/utils/environment.py` | 6.8 KB | KEEP | Code, tests or configuration needed to reproduce the results | run_check.py / test suite / README | keep |
| `src/utils/manifest.py` | 6.8 KB | KEEP | Code, tests or configuration needed to reproduce the results | run_check.py / test suite / README | keep |
| `src/visualization/__init__.py` | 0.0 KB | KEEP | Code, tests or configuration needed to reproduce the results | run_check.py / test suite / README | keep |
| `src/visualization/paper_figures.py` | 26.6 KB | KEEP | Code, tests or configuration needed to reproduce the results | run_check.py / test suite / README | keep |
| `tests/fixtures/hallucinated_tiny.txt` | 0.1 KB | KEEP | Code, tests or configuration needed to reproduce the results | run_check.py / test suite / README | keep |
| `tests/test_agreement.py` | 6.7 KB | KEEP | Code, tests or configuration needed to reproduce the results | run_check.py / test suite / README | keep |
| `tests/test_checkpointing.py` | 2.6 KB | KEEP | Code, tests or configuration needed to reproduce the results | run_check.py / test suite / README | keep |
| `tests/test_collapse_audit.py` | 1.1 KB | KEEP | Code, tests or configuration needed to reproduce the results | run_check.py / test suite / README | keep |
| `tests/test_environment.py` | 1.8 KB | KEEP | Code, tests or configuration needed to reproduce the results | run_check.py / test suite / README | keep |
| `tests/test_grammar_validation.py` | 5.2 KB | KEEP | Code, tests or configuration needed to reproduce the results | run_check.py / test suite / README | keep |
| `tests/test_h1_pilot_analysis.py` | 43.6 KB | KEEP | Code, tests or configuration needed to reproduce the results | run_check.py / test suite / README | keep |
| `tests/test_incident_clients.py` | 11.7 KB | KEEP | Code, tests or configuration needed to reproduce the results | run_check.py / test suite / README | keep |
| `tests/test_injection_labeler.py` | 5.8 KB | KEEP | Code, tests or configuration needed to reproduce the results | run_check.py / test suite / README | keep |
| `tests/test_labeler_spot_check.py` | 2.1 KB | KEEP | Code, tests or configuration needed to reproduce the results | run_check.py / test suite / README | keep |
| `tests/test_leakage_checks.py` | 3.6 KB | KEEP | Code, tests or configuration needed to reproduce the results | run_check.py / test suite / README | keep |
| `tests/test_malware_labeler.py` | 13.7 KB | KEEP | Code, tests or configuration needed to reproduce the results | run_check.py / test suite / README | keep |
| `tests/test_manifest.py` | 2.8 KB | KEEP | Code, tests or configuration needed to reproduce the results | run_check.py / test suite / README | keep |
| `tests/test_misclassification.py` | 1.7 KB | KEEP | Code, tests or configuration needed to reproduce the results | run_check.py / test suite / README | keep |
| `tests/test_naming_grammar.py` | 3.5 KB | KEEP | Code, tests or configuration needed to reproduce the results | run_check.py / test suite / README | keep |
| `tests/test_registry_clients.py` | 5.0 KB | KEEP | Code, tests or configuration needed to reproduce the results | run_check.py / test suite / README | keep |

## Local-only files (untracked or gitignored)

| Path | Size | Group | Reason | Rebuilt by | Note |
|---|---|---|---|---|---|
| `__pycache__/ (8 folders, 73 files)` | 1.31 MB | GENERATED | Python bytecode cache | rebuilt automatically on import | already ignored |
| `.pytest_cache/ (5 files)` | 32.0 KB | GENERATED | pytest cache | `python -m pytest` | already ignored |
| `.DS_Store, data/.DS_Store, reports/.DS_Store, src/.DS_Store` | 34.0 KB | GENERATED | macOS Finder metadata | created by Finder | already ignored; delete locally |
| `paper/main.aux, paper/main.log` | 30.9 KB | GENERATED | LaTeX build files | `pdflatex main.tex` (×2) in paper/ | already ignored |
| `paper_dib/dib_main.{aux,log,out,spl}` | 31.5 KB | GENERATED | LaTeX build files | `pdflatex dib_main.tex` (×2) in paper_dib/ | already ignored |
| `.venv/ (392 MB)` | 392.00 MB | GENERATED | Virtual environment (includes a stray `.venv/bin/<math-symbol>thon` file created by the venv) | `python3 -m venv .venv && .venv/bin/pip install -r requirements.txt` | already ignored |
| `notes/paper_outline_msr2027.md.pdf` | 78.0 KB | KEEP (local only) | Paper outline — must stay out of the repo | — | ignored via `notes/`; keep that rule |

`.git/` (5.9 MB) is git's own store and is not classified.
