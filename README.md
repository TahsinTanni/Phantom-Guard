# Predictable Hallucination, Preventable Payload

Linking LLM artifact-naming grammar to injection-payload risk across
package and agent-skill ecosystems.

**Status: Phase 0 complete.** This README will be filled out fully per the
spec (dataset licenses, Kaggle setup, runtime estimates, ethics, citation)
as later phases add real content. Right now it documents what exists.

## 1. Research question (current)

Does predictable LLM-hallucination-style naming grammar in software
artifacts (packages, and separately, agent skills) correlate with — and
precede more quickly — the presence of prompt-injection payloads in that
artifact's documentation, relative to a matched sample of non-flagged real
artifacts? See `reports/` for the living hypothesis/novelty audit.

## 2. What exists as of Phase 0

- `src/utils/environment.py` — Kaggle/local/Colab environment detection and
  path resolution. Data collection is explicitly NOT assumed to run on
  Kaggle (see module docstring) — Kaggle consumes frozen, versioned
  snapshots as a read-only input Dataset.
- `src/utils/manifest.py` — dataset and experiment manifest generation
  (SHA256 checksums, git commit, config hash, package versions, license,
  data-generating-process tag).
- `src/utils/checkpointing.py` — restart-safe batch processing for
  long-running, disconnect-prone operations (downloads, feature
  extraction, embeddings, training, inference).
- `src/data/leakage_checks.py` — automated leakage detection (duplicate,
  name-family, temporal, label, documentation-version). Raises loudly on
  severe leakage via `assert_no_severe_leakage`.
- `src/statistics/power_analysis.py` — approximate power analysis for H1
  (logistic regression) and H1b (Cox PH), used to drive the go/no-go gate.
- `src/statistics/phase0_gate.py` — consumes pilot counts, produces
  `reports/phase0_go_no_go.md` with a GO / GO_WITH_REDUCED_SCOPE / NO_GO
  decision.
- `config/base.yaml` — project-wide config, including data-source status
  flags (several sources are marked `needs_verification` — do not build
  parsers against them until license/availability is confirmed).
- `tests/` — unit tests for all of the above.

## 2b. Phase 1 (in progress) — package collection layer

- `src/data/registry_clients.py` — async PyPI/npm metadata + **full README
  text** fetchers. Ported from the prior notebook's `fetch_pypi_meta`/
  `fetch_npm_meta` (cells 11, 23, 25b), extended to capture documentation
  text (needed for injection labeling, Phase 2) and raw publish timestamps
  instead of fetch-time-relative `age_days` (temporal-leakage fix).
- `src/data/naming_grammar.py` — the H1 independent-variable classifier.
  `COMPOUND_SUFFIXES`/`COMPOUND_PREFIXES` ported verbatim from the prior
  notebook's Cell 18, repurposed from candidate-generation to
  observed-name classification. Also carries a `TREND_SUFFIXES` list
  (`-turbo`/`-pro`/`-plus`/etc.) distinguishing hallucination-trend naming
  from legitimate-compound naming — these were conflated in the original
  notebook's single suffix list and are now tracked separately since H1
  needs that distinction. Includes the typosquat generator ported from
  Cell 12 (pure-Python Levenshtein fallback, no hard `rapidfuzz`
  dependency).
- `src/data/seed_lists.py` — control-sample name sources, ported from
  cells 9/10 (hugovk top-PyPI-packages JSON; npm search-API fallback —
  starting from the fallback path specifically because that's what
  actually worked in the original run).
- `src/data/collect_packages.py` — orchestration layer that did NOT exist
  before as reusable code. Unifies the prior notebook's four separate
  bespoke JSON-checkpoint-dict patterns (cells 11, 19, 23, 25b) onto the
  single Phase 0 `CheckpointManager`, and auto-generates a dataset
  manifest on completion.

**Not yet ported / built:** confirmed-incident collection (GHSA/OSV/
`pypa/malware-reports`) and agent-skill corpus ingestion (MalSkillBench/
SkillJect/DDIPE) — these have no equivalent in the original notebook and
are the next piece of Phase 1.

**Known environment limitation:** `tests/test_registry_clients.py`
requires `aiohttp` + `pytest-asyncio`. Not installed in the sandbox this
was developed in (no network access there); verified via code review
against the original notebook's already-live-tested fetch logic instead.
Both packages are present in Kaggle's default image — run
`pytest tests/test_registry_clients.py -v` there or after
`pip install aiohttp pytest-asyncio` locally.

## 2c. Phase 1b (in progress) — confirmed-incident collection

- `src/data/incident_clients.py` — GHSA (`api.github.com/advisories`) and
  OSV.dev clients. Fetches and normalizes advisory metadata ONLY
  (package name, ecosystem, summary/description text, dates, references).
  Deliberately does NOT compute `injection_present` — that's Phase 2's
  separate, reviewed labeling step, kept apart so labeling decisions stay
  auditable independent of collection code.
- `src/data/collect_incidents.py` — orchestration: bulk GHSA fetch ->
  candidate package list -> per-package OSV cross-check (checkpointed) ->
  dedupe (prefers GHSA on exact advisory-ID collision, keeps distinct
  advisory IDs as separate records) -> manifest.
- `tests/test_incident_clients.py` — 8 tests, fully mocked `requests`
  calls, verified passing (46/46 total across the whole suite as of this
  phase, all runnable without network in this sandbox since `requests`
  — unlike `aiohttp` — was available for mocking here).

**Not yet built:** Phase 2 injection-payload labeling/taxonomy (reads the
`description`/`summary` text these collectors capture and applies the
10-category taxonomy from the original spec) — that's next after this
phase is confirmed on Kaggle.

## 3. Installation

```bash
python -m venv .venv
source .venv/bin/activate   # or .venv\Scripts\activate on Windows
pip install -r requirements.txt
```

## 4. Running tests

```bash
pytest tests/ -v
```

## 5. Kaggle setup (Phase 0 relevant parts only)

1. Data collection happens OFF Kaggle (local machine or a scheduled
   runner) — see `src/utils/environment.py` docstring for rationale.
2. Collected, checksummed Parquet/JSONL snapshots + their manifests
   (`src/utils/manifest.py`) are packaged as a Kaggle Dataset.
3. Attach that Dataset to a Kaggle Notebook as input. Kaggle code reads
   from `/kaggle/input/<dataset-slug>/...` (resolved automatically via
   `get_paths()` when `detect_environment()` returns `"kaggle"`), and
   writes only to `/kaggle/working/...`.
4. At the top of every notebook, call:
   ```python
   from src.utils.environment import print_environment_banner
   paths = print_environment_banner()
   ```

## 6. Phase 0 gate

Before any data collection beyond a small pilot, run:

```bash
python -m src.statistics.phase0_gate
```

(Currently runs with placeholder example counts — replace
`Phase0PilotCounts` in `if __name__ == "__main__":` with real pilot numbers
once Phase 1 pilot collection exists.) This produces
`reports/phase0_go_no_go.md` with an explicit decision and reasons. **Do
not proceed to full-scale modeling if the decision is NO_GO.**

## 7. Data sources — verification status

See `config/base.yaml` → `data_sources`. Several sources referenced in the
research proposal (`pypa/malware-reports`, MalSkillBench, SkillJect, DDIPE,
the NymGuard repo) are marked `needs_verification` — their license,
current availability, and structure have not yet been confirmed. Do not
build ingestion code against a `needs_verification` source until its
status is updated, per the project's explicit source-verification
requirement.

## 8. Limitations acknowledged at this stage (see full audit)

- Confirmed-incident base rates may be too low to power H1b (survival
  analysis); the gate exists specifically to catch this before wasted
  effort.
- Real-world incident corpora likely have a detection-bias confound with
  naming-grammar flagging (sources that watch known hallucination-prone
  slots more closely). See `src/data/leakage_checks.py` docstrings and the
  living proposal audit in `reports/` for the planned sensitivity analysis.
- Agent-skill corpora (MalSkillBench, DDIPE, SkillJect) are predominantly
  red-team/synthetic, not in-the-wild — cross-artifact generalization
  claims (H2) must be reported split by `data_generating_process`, never
  pooled into one number.

## 9. Ethics

All malicious/injection artifact text is handled as inert strings only.
Nothing in this repository executes artifact contents, publishes malicious
packages or skills, or targets a live registry or production agent. Any
adversarial-evasion generation (later phases) runs in a sandboxed, local,
offline harness only.

## 10. Citation

TBD — added once the paper has a stable draft.
