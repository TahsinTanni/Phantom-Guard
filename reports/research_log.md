# Phantom Guard — Research Log

**Scope of this document:** everything actually executed and verified, from Phase 0 through the second-round correction of the ecosystem-stratified statistical analysis (Section 5.5) and the campaign-level power analysis that followed it (Section 5.8). Does not include the later "agent-skill pre-registration classifier" pivot proposal — that was discussed but never started, and is excluded here per request.

**Working title:** *Naming-Grammar Signals and Malicious-Payload Sophistication in Real-World Package Squatting Incidents* (project codename: Phantom Guard)

---

## 1. Project Identity and Research Question

**Original motivating question:** does naming-grammar predictability in software package names (the kind of compound/trend-suffix pattern an LLM is prone to hallucinate) correlate with the presence and/or sophistication of malicious content in the resulting package, among real-world confirmed-malicious incidents?

**This evolved during the work** (see Section 4) from an initial framing around "AI-agent-targeting injection payloads" to a corrected framing around "malware payload sophistication," because the actual data did not contain the former construct. This correction is itself one of the project's findings, not a detour from it.

---

## 2. Infrastructure (Phase 0)

Built before any data collection, to make every later claim auditable rather than asserted.

| Module | Purpose |
|---|---|
| `src/utils/environment.py` | Kaggle/local/Colab environment detection and path resolution. Supports a `force_env` override for deterministic testing. |
| `src/utils/manifest.py` | Dataset and experiment manifest generation — SHA256 checksum, git commit hash, config hash, installed package versions, license field, and a `data_generating_process` provenance tag (`real_world_observed` used throughout). |
| `src/utils/checkpointing.py` | Restart-safe batch processing via an append-only JSONL ledger with atomic writes. Used by every long-running collection operation so a Kaggle session disconnect doesn't force a full restart. |
| `src/data/leakage_checks.py` | Five automated leakage checks (duplicate, name-family, temporal, label-correlation, documentation-version), each returning a severity level; `assert_no_severe_leakage()` raises on severe findings rather than allowing a pipeline to continue silently. |
| `src/statistics/power_analysis.py` | Approximate power-analysis formulas for a single-covariate logistic regression (Hsieh/Demidenko-style) and for Cox proportional hazards (Schoenfeld formula) — built to gate whether a planned hypothesis test is even reachable at a given pilot sample size before committing further effort. |
| `src/statistics/phase0_gate.py` | Consumes pilot counts and produces a GO / GO-WITH-REDUCED-SCOPE / NO-GO decision with stated reasons, written to `reports/phase0_go_no_go.md`. |

**Verification:** run repeatedly on real Kaggle sessions across the project's lifetime; test count grew as phases were added — 26 passed (Phase 0 alone, after one real bug fix described in Section 8) → 43 → 48 → 53 → 62 → 77 → 82 → 84 → 88/89 → **102 (final state, after the Section 5.5 fixes and their regression tests)**.

---

## 3. Data Collection

### 3.1 Control sample — real, non-flagged packages (Phase 1)

**Source code:** `src/data/registry_clients.py`, `src/data/seed_lists.py`, `src/data/collect_packages.py`.

**Provenance:** ported from the original exploratory notebook (`final-reviewer-model-by-claude.ipynb`, a prior DeBERTa-based package-hallucination-existence classifier project), specifically its async PyPI/npm metadata-fetching cells and its top-package seed-list cells. Two deliberate changes from the original:
1. **Full README text is now captured** (`readme_text` field, from PyPI's `info.description` and npm's `readme` field) — the original only captured one-line summaries, which would have been insufficient for any text-based labeling task.
2. **Raw ISO publish timestamps are stored** (`first_published_at`) instead of an `age_days` value computed at fetch time, which would silently change on every rerun.

**Data sources:**
- PyPI JSON API (`pypi.org/pypi/{name}/json`) — verified accessible, no auth required.
- npm registry API (`registry.npmjs.org/{name}`) — verified accessible, no auth required. Known limitation: `readme` field is sometimes absent for large packages under npm's abbreviated response behavior.
- Seed name lists: hugovk's `top-pypi-packages.min.json` (popularity-ranked PyPI names) and npm's public search API (`registry.npmjs.org/-/v1/search`) as a fallback source, since the originally-planned `npm-high-impact` package source failed to parse in practice.

**What was actually collected and verified live on Kaggle:** 20 real PyPI packages (`boto3`, `requests`, `numpy`, etc.) — 100% README coverage (20/20 non-empty), 0% grammar-flagged (correctly so, since these are old, plain-named, highly popular packages, not compound/trend-pattern names).

**Status / open gap:** this control sample was collected and validated as a working pipeline, but **was not used in the final statistical analysis** (Section 5). The H1 analysis that was actually run compares grammar-flagged vs. non-flagged names *within* the confirmed-incident corpus itself, not against this external control sample. Using this control sample in a matched-comparison design is still listed as unfinished work (Section 7) — **unchanged by the Section 5.5 correction**.

### 3.2 Confirmed-incident corpus (Phase 1b)

**Source code:** `src/data/incident_clients.py`, `src/data/collect_incidents.py` — built from scratch, no equivalent in the original notebook.

**Data sources:**
- GitHub Security Advisories API (`api.github.com/advisories`), filtered to `type=malware` and ecosystems `pip`/`npm`. Verified publicly accessible without authentication at pilot volume.
- OSV.dev API (`api.osv.dev/v1/query`), queried per-package as a cross-check/corroboration source against GHSA-surfaced package names. Verified publicly accessible.

**Pipeline:** bulk paginated GHSA fetch → build a candidate package-name list → per-package OSV cross-check (checkpointed, resumable) → deduplicate on `(ecosystem, package_name, advisory_id)`, preferring GHSA on exact-key collision, keeping distinct advisory IDs from either source as separate records → write combined JSONL + dataset manifest.

**What was actually collected and verified live on Kaggle, across multiple independent runs:**
- Run 1: 399 unique deduplicated incident records.
- Run 2 ("clean single-pass" rerun): 396 unique deduplicated incident records.
- A later diagnostic session (the one producing Section 5.5's correction) worked from a **401-record pull**, frozen to disk as a permanent snapshot (see Section 5.5) specifically to stop this drift from confounding further analysis.
- The record-count differences across runs (399 / 396 / 401) reflect GHSA being a **live, non-static API** — advisory counts shift slightly between pulls. This is a known reproducibility caveat (Section 8), not a bug. **It is no longer a live risk for the reported result**, since Section 5.5's numbers are computed against a single frozen, checksummed snapshot, not a live pull.
- Manual inspection confirmed the corpus contains genuine malware advisories (e.g. `boto4`, `reqcrypts`, `requests-crypt` — visible typosquats of `boto3`/`requests`), not unrelated CVE noise, confirming the `type=malware` filter worked as intended.

---

## 4. Labeling: the construct-validity correction

This is the most important methodological event in the project's first round, and is documented in detail because it shapes everything downstream — including the Section 5.5 correction, which is a second instance of the same failure mode.

### 4.1 First attempt — injection taxonomy (superseded)

**Source code (kept in the repo but not used in final analysis):** `src/labeling/injection_taxonomy.py`, `src/labeling/injection_labeler.py`.

A 10-category taxonomy was built (direct instruction override, system-prompt impersonation, tool-use manipulation, data exfiltration, external resource retrieval, unauthorized execution, credential/token manipulation, context poisoning, indirect prompt injection, benign-instruction-like as a negative class), targeting text designed to manipulate an AI agent reading documentation — matching the project's original framing.

Applied to the 399-record incident corpus: **25.3% flagged** (101/399), with all matches falling into only three categories (`unauthorized_execution_instruction`, `external_resource_retrieval`, `data_exfiltration_instruction`) and **zero matches** in any of the agent-specific categories (`direct_instruction_override`, `system_prompt_impersonation`, `tool_use_manipulation`, `indirect_prompt_injection`).

**Manual inspection of matched text** (requested specifically because the category distribution looked suspicious) revealed the matched spans were things like *"Category: MALICIOUS - The campaign has clearly malicious intent, like infostealers"* — generic third-party malware-scanner verdict boilerplate, not the artifact's own documentation and not agent-directed content. Further inspection of full `description` fields confirmed GHSA/OSV's text is **forensic analyst narration of malware behavior**, written in the third person by a security researcher, not text embedded in the malicious package meant to manipulate a reader (human or AI).

**Conclusion:** the injection taxonomy targets a construct this data source does not contain. It is retained in the codebase, explicitly scoped in its own docstring as reserved for a future corpus that genuinely contains agent-directed text (e.g., an agent-skill corpus), and was not applied to the final analysis.

### 4.2 Corrected taxonomy — malware payload sophistication

**Source code:** `src/labeling/malware_taxonomy.py`, `src/labeling/malware_labeler.py`.

Six categories, originally built with regex patterns **derived directly from real examples pulled from the actual pilot corpus** (not written from first principles before looking at data, which was the root cause of the first attempt's failure):
- `obfuscated_payload_execution` (e.g. base64/gzip/zlib-decode piped into `exec()`)
- `hidden_install_hook` (disguised `setup.py` custom install commands)
- `credential_or_wallet_exfiltration`
- `remote_backdoor_access` (e.g. Flask server bound to `0.0.0.0`, persistence via registry keys)
- `remote_payload_retrieval` (download-and-execute dropper pattern)
- `brand_impersonation_narrative` (advisory text explicitly describing name/brand mimicry)

**Independence guarantee (both taxonomies):** the labeling function's signature accepts only free text — no package name, no naming-grammar classification — enforced both by convention (documented) and by a structural test asserting the function signature contains no such parameter. This is required so the later naming-grammar-vs-payload association test is not circular.

**First-round bug found and fixed:** the first version of the malware patterns used exact-verb matching (`send `, `download `) which failed to match real conjugated forms (`sends`, `downloads`) found in actual advisory text — caught by manually running the labeler against realistic examples rather than only hand-picked test strings, then fixed to tolerate verb conjugation (`\bsend\w*\s+...`) and covered with regression tests.

**Second-round bug found and fixed — see Section 5.5.** The patterns above, while verb-conjugation-tolerant, were discovered in a later session to have been derived **almost entirely from PyPI examples**, with near-zero coverage of npm/JS-specific phrasing. This produced a flat 0/198 npm malware-flag rate across four independent pipeline executions before being diagnosed and fixed. See Section 5.5 for the full account.

**First-round applied-corpus numbers** (before the Section 5.5 fix; **superseded, kept for history**): ~28.8% flagged (114–115 of 396–399 records), category distribution led by `credential_or_wallet_exfiltration` (~42–44), `remote_backdoor_access`/`remote_payload_retrieval` (~34–37 each), `brand_impersonation_narrative` (~17–18), `obfuscated_payload_execution` (~10), `hidden_install_hook` smallest (~4).

---

## 5. Statistical Analysis (first round — superseded, see 5.5)

**Source code:** `src/statistics/h1_pilot_analysis.py`.

### 5.1 Design

`attach_grammar_labels()` computes the naming-grammar classification (`src/data/naming_grammar.py`, ported from the original notebook's Cell 18 compound-suffix/prefix logic, repurposed from candidate-*generation* to observed-name *classification*, plus a new `TREND_SUFFIXES` list for hallucination-flavored patterns like `-turbo`/`-pro`) onto each already-malware-labeled incident record, joining strictly **after** both labels exist independently — this join is for analysis only and does not feed one label into the other's computation.

This produces a 2×2 contingency table: grammar-flagged vs. not, crossed with malware-payload-present vs. not, computed **within the confirmed-incident corpus** (not against the external control sample — see the open gap noted in Section 3.1).

### 5.2 Results (pooled, unadjusted) — SUPERSEDED, see 5.5

Two independent runs, both via Fisher's exact test:

| Run | n | Rate when flagged | Rate when not flagged | Odds ratio | p-value |
|---|---|---|---|---|---|
| 1 | 399 | 21.3% | 32.9% | 0.55 | 0.023 |
| 2 (clean rerun) | 396 | 21.1% | 31.7% | 0.58 | 0.046 |

**These numbers are from the first-round labeler, which is now known to have had near-zero sensitivity on npm text. They are kept here as history, not as a result to cite. See Section 5.5 for the corrected analysis.**

### 5.3 Ecosystem-stratified results — SUPERSEDED, see 5.5

A `pd.crosstab` split by ecosystem was checked to rule out the pooled result being an artifact of ecosystem mixing (a Simpson's-paradox-style confound). Per-ecosystem Fisher's exact tests (clean-rerun data, first-round labeler):

| Ecosystem | n | Rate when flagged | Rate when not flagged | Odds ratio | p-value |
|---|---|---|---|---|---|
| npm | 197 | 8.5% | 11.6% | 0.71 | 0.62 (n.s.) |
| PyPI | 199 | 36.0% | 50.3% | 0.56 | 0.10 (n.s.) |

**In hindsight, the npm row above is now understood to reflect near-total labeler insensitivity on npm text (a later diagnostic session found a flat 0/198 npm flag rate using the same unpatched labeler against a fresh pull), not a genuine weak effect.** Kept as history.

**Cochran-Mantel-Haenszel test** (`run_cmh_test`) was run to pool evidence across strata while still controlling for ecosystem:

| Run | Common OR | Chi² | p-value |
|---|---|---|---|
| 1 | 0.580 | — | 0.056 |
| 2 (clean rerun) | 0.595 | 3.33 | 0.068 |

### 5.4 Honest interpretation (first round) — SUPERSEDED

The original interpretation here read a reproducible, directionally-consistent signal into these numbers. **That interpretation does not survive Section 5.5's correction** — the apparent consistency was partly an artifact of a near-zero npm flag rate making the npm stratum trivially "weak but same-direction" by default. Retained for history; superseded in full by 5.5.

### 5.5 Second-round correction

**Trigger.** Across the first-round log above and three further independent pipeline executions in a later session, the pooled odds ratio took **four different values with inconsistent direction**: OR≈0.58 (Run 1/2, log), OR=2.39 (an undocumented third run, opposite sign), and — mid-session, before the fixes below — intermediate values as high as OR=178 while debugging. This volume of disagreement across nominally-identical reruns was itself the signal that something structural was wrong, not sampling noise.

**Bug #1 — npm taxonomy vocabulary gap.** Diagnosis: a `pd.crosstab` of `has_malware` by `(ecosystem, is_flagged)` showed **npm malware-flagged = 0 for every cell**, not just the grammar-flagged subgroup — meaning the labeler was failing on npm entirely, independent of naming grammar. Manually inspecting real npm advisory text (e.g. `line-through`, `box-sign-client`, `tailwind-contact-forms`, `real-router-telemetry`) against each category's compiled regex confirmed the cause: patterns required PyPI-specific vocabulary (`setup.py`, `pip install`, `exec`/`eval`) and PyPI-style exfiltration verbs (`exfiltrat`/`steal`/`harvest`), which npm advisories simply don't use — npm text instead uses `preinstall`/`postinstall` hooks, JS-specific obfuscators (`obfuscator.io`-style string-array encoding), and plainer verbs (`reads`, `collects`, `sends`, `POSTs`, `embeds`).

*Fix:* added npm-aware patterns to four of six categories (`hidden_install_hook`, `obfuscated_payload_execution`, `credential_or_wallet_exfiltration`, `remote_backdoor_access`), each grounded in real npm examples pulled from the corpus, matching the project's existing "patterns from data, not first principles" convention (Section 4.2).

*A deliberate reversion within this fix:* an initial addition flagging GHSA's generic no-detail fallback template (*"Any computer that has this package installed... should be considered fully compromised..."*) as `remote_backdoor_access` was tested, found to inflate flags on 26 records sharing only that boilerplate (not a real shared mechanism — the same text appears verbatim across unrelated incidents like `daytona-test-*`, `@yongot/canary-mcp-*`, `cat-sis2go-utils`), and **reverted** for consistency with the project's own `test_does_not_flag_scanner_verdict_boilerplate` principle: a confirmed-malicious record with no described mechanism is not evidence of payload *sophistication*. This is the same construct-validity failure mode as Section 4.1, caught the same way (manual inspection over trusting an aggregate number), occurring a second time in a narrower form.

**Bug #2 — npm campaign-level non-independence.** Diagnosis: after fixing Bug #1, the npm odds ratio spiked to an implausible **178 (p=5.1×10⁻⁷)** on a table with single-digit cells (`[[6,1],[3,89]]`). A Haldane-Anscombe correction (adding 0.5 to every cell) only reduced it to 110.8, ruling out simple small-sample artifact as the sole cause. Manual inspection of the grammar-flagged, malware-positive npm records found they collapsed into only 3 underlying campaigns (`daytona-test-*` ×3, `@yongot/canary-mcp-*` ×2, `cat-sis2go-utils` ×1) — GHSA, OSV, and Amazon Inspector frequently report the **same incident multiple times** under different `advisory_id`s (missed by `deduplicate_incidents()`'s advisory_id-keyed dedup, which is correct for its stated purpose but not designed to catch this), and **separately**, one attacker often squats **multiple distinct package names** under one campaign with near-identical description text. Both inflate the effective n without adding independent evidence, violating Fisher's/CMH's independence assumption.

*Fix:* added `collapse_to_campaign_level()` to `h1_pilot_analysis.py` (new, tested, reusable project code — not notebook-only logic), performing two explicit stages: (1) name-level collapse on `(ecosystem, package_name)`, catching GHSA/OSV re-reports of the same package; (2) campaign-signature collapse on description-text prefix, catching multi-name campaigns. Both stages use an "any member positive" aggregation rule for both the grammar-flag and malware-outcome fields — deliberately, since different name variants within one campaign can carry different naming-grammar classifications even though they share one payload; picking a single representative record (an earlier, discarded attempt) silently drops real campaigns from one side of the table. `build_campaign_signature()` explicitly excludes GHSA's generic boilerplate template from being usable as a grouping key (verified via regression test), since that text is identical across genuinely unrelated incidents and would otherwise falsely merge them.

**Verification.** 5 new regression tests added for the campaign-collapse logic (`tests/test_h1_pilot_analysis.py`) and 4 new regression tests for npm-pattern coverage (`tests/test_malware_labeler.py`), pinned to real corpus examples. Full suite: **102/102 passing** (up from 88/89 at the end of the first round).

**Frozen snapshot.** The 401-record pull used for this correction was frozen to `data/frozen/incidents_snapshot.jsonl` with a manifest (`build_dataset_manifest`, `preprocessing_version="v1-postfix"`), specifically to stop further live-API drift from confounding comparison across sessions (addresses Section 7, item 4, for this snapshot going forward — the broader "freeze one snapshot for final analysis" item remains open for the full corpus).

### 5.6 Final result (campaign-level, frozen snapshot)

| Stratum | n (campaigns) | Odds Ratio | 95% CI | p-value |
|---|---|---|---|---|
| Pooled | 142 | 0.849 | [0.399, 1.803] | 0.702 |
| npm | 42 | 1.545 | [0.424, 5.633] | 0.530 |
| PyPI | 100 | 0.702 | [0.272, 1.812] | 0.472 |
| CMH (ecosystem-adjusted) | 142 | 0.928 | [0.433, 1.991] | 0.848 |

95% CIs added in Section 5.11: Woolf (log) interval for the sample OR from statsmodels `Table2x2`; for CMH, the Robins-Breslow-Greenland interval for the Mantel-Haenszel OR from statsmodels `StratifiedTable`.

### 5.7 Honest interpretation (superseding 5.4)

**No statistically significant association, in either direction, pooled or ecosystem-adjusted, in either ecosystem individually.** This is a genuine null result at current sample size (n=142 independent campaigns after correcting for non-independence) — it is neither the reversed/inflated finding seen transiently during debugging (OR as high as 178 or 2.39) nor a confirmation of the original directional hypothesis from Section 5.4's first-round reading. The earlier apparent "reproducible, directionally-consistent signal" (Section 5.4) does not survive once the npm labeler insensitivity and the campaign-duplication inflation are both corrected. This should be read alongside `src/statistics/power_analysis.py`: at n=142 campaigns with the observed effect sizes, the study is very likely underpowered to detect a true effect of plausible magnitude, so "no significant association" should not be read as "no effect exists" — **Section 5.8 now quantifies this**; see Section 7 for the prioritized path to a properly powered follow-up.

### 5.8 Power analysis at the campaign-level n (independent local reproduction)

**Context.** Section 7 item 1 asked whether the 5.7 null is informative or merely underpowered. This section answers it. It was run in a **fresh local environment** (VS Code, clean `.venv`, Python 3.14) by a second person who had not worked on the code before, from the persisted `project_p0_edited` folder plus `data/frozen/incidents_snapshot.jsonl` — i.e. an independent reproduction, not a rerun inside the original Kaggle session. Script: `run_check.py` at the project root; output saved to `results/power_campaign_level.json`.

**Reproduction check first.** Every Section 5.6 number reproduced exactly from the frozen snapshot: 401 records → 142 campaigns; pooled OR 0.849 / p 0.702; npm OR 1.545 / p 0.530; PyPI OR 0.702 / p 0.472; CMH OR 0.928 / p 0.848. Record-level malware-flag rates with the Section 5.5 patch: npm 59.5%, PyPI 54.7% (confirming the npm-zero bug is gone in the persisted code). Taxonomy pattern counts matched the patched version (6/7/6/5 in the four npm-patched categories vs 4/3 in the two untouched ones). This also closes Section 7 item 11 (permanence): the persisted folder is the fixed one, and the code runs with no Kaggle dependency.

**Method.** `logistic_regression_power()` from `src/statistics/power_analysis.py`, called with the *observed* campaign-level inputs rather than the module's pilot defaults: `p_control` = outcome rate among non-grammar-flagged campaigns, `exposure_prevalence` = the observed flagged share (not the 0.5 the module assumes for a 1:1 matched design — the actual split is unbalanced, which costs power). Achieved power at the actual n was computed by inverting the same Hsieh/Demidenko approximation. Target odds ratios were fixed on practical grounds (0.5 / 0.67 / 1.5 / 2.0 / 3.0), not read off the data, per the module's own circularity warning.

**Result (pooled, n = 142 campaigns).**

| Target OR | Achieved power at n=142 | n required for 80% power |
|---|---|---|
| 2.0 or 0.5 | ≈ 0.43 | ≈ 349 |
| 3.0 | ≈ 0.81 | < 142 |
| 1.5 or 0.67 | ≈ 0.18 | > 1,000 |

Per ecosystem alone: npm (n=42) ≈ 0.18 power at OR 2.0; PyPI (n=100) ≈ 0.28.

**Interpretation.** The Section 5.7 null is **underpowered for any plausible effect size**. At n=142 the design only reliably detects an odds ratio of ~3 or more; it would miss a doubling/halving of odds more often than not (43% power), and a modest 1.5× effect almost always. The null therefore rules out *only* very large effects and must not be read as "no effect exists." The per-ecosystem strata are far too small to say anything on their own, which also means the apparent sign flip between npm (OR 1.5) and PyPI (OR 0.7) in 5.6 is uninterpretable at present — not evidence of effect modification.

**Decision.** Corpus growth is confirmed as the gating next step: roughly **2.5× the current campaign count (~350 independent campaigns)** to reach 80% power for OR = 2.0 with a single binary exposure. This is a floor — the planned controlled regression (Section 7 item 3) adds covariates and will need more. Since the campaign-collapse ratio in this snapshot is ~2.8 raw records per campaign, that implies on the order of **1,000 raw GHSA/OSV records** before collapse, which means expanding beyond the 5-page GHSA pull used so far (older advisories, and/or additional sources such as `pypa/malware-reports` once its status is verified per `config/base.yaml`).

### 5.9 Text-source sensitivity: DV text × grouping text (review.md A2 / D1)

**Context.** review.md A2 (corrected version) found that the 5.6 result depends on which advisory text the DV is read from: every package has a GHSA record and an OSV record, and stage 1 of `collapse_to_campaign_level()` used "any record positive" across *sources*. D1 asks for one canonical text per package, with the text source and the campaign grouping varied as separate switches.

**Code.**
- `src/statistics/h1_pilot_analysis.py`: `select_canonical_record(records, prefer)` returns one record per (ecosystem, package_name). Records are grouped per source as **lists**, `prefer` ∈ {ghsa, osv} is taken first with fallback to the other source, and within a source the earliest `published_at` wins. `collapse_to_campaign_level()` gains `text_source` and `group_on` (each any/ghsa/osv, default any). With `text_source ≠ any`, stage 1 reads one canonical record and does not aggregate across sources. Stage 2 (across names in a campaign) is unchanged.
- `run_check.py`: `--text-source {any,ghsa,osv}`, `--group-on {any,ghsa,osv}`. Defaults reproduce 5.6 exactly (verified: 142 campaigns, [[20,17],[61,44]], OR 0.849, p 0.702, CMH 0.928 / 0.848). Non-default runs write `results/power_campaign_level__text-<x>__group-<y>.json`; the default output file is unchanged apart from a new `settings` key.
- `tests/test_h1_pilot_analysis.py`: 8 new tests, including a regression test for the same-source overwrite and a snapshot test that pins the defaults to 5.6. Suite: **110 passed** (was 102).

**What "any" means.** `text_source=any` is "any record from any source positive" (5.6). `group_on=any` is the first record in input order (5.6). In the frozen snapshot that is the GHSA record for 200/200 packages, so `group_on=any` and `group_on=ghsa` give the same grouping. A test checks this.

**Same-source duplicate.** One package (`memoryos`, PyPI) has two OSV records: MAL-2026-16475 (published 2026-09-23T00:00, regex-positive) and PYSEC-2026-3987 (19:52 the same day, regex-negative). The first A2 table indexed records in a dict, so the later PYSEC record overwrote the MAL record. That is the source of the 60-vs-61 discrepancy noted in A2. With list indexing, OSV-only text reproduces the any-source table exactly.

**Result: 3×3 grid** (reproduce with `python run_check.py --text-source X --group-on Y`):

| DV text | Grouping text | n campaigns | Pooled table | OR [95% CI] | p | npm table, OR [95% CI] / p | PyPI table, OR [95% CI] / p | CMH OR [95% CI] / p | Power at OR 2.0 |
|---|---|---|---|---|---|---|---|---|---|
| any | any | 142 | [[20,17],[61,44]] | 0.849 [0.399, 1.803] | 0.702 | [[7,7],[11,17]] 1.545 [0.424, 5.633] / 0.530 | [[13,10],[50,27]] 0.702 [0.272, 1.812] / 0.472 | 0.928 [0.433, 1.991] / 0.848 | 0.43 |
| any | ghsa | 142 | [[20,17],[61,44]] | 0.849 [0.399, 1.803] | 0.702 | [[7,7],[11,17]] 1.545 [0.424, 5.633] / 0.530 | [[13,10],[50,27]] 0.702 [0.272, 1.812] / 0.472 | 0.928 [0.433, 1.991] / 0.848 | 0.43 |
| any | osv | 142 | [[20,17],[61,44]] | 0.849 [0.399, 1.803] | 0.702 | [[7,7],[11,17]] 1.545 [0.424, 5.633] / 0.530 | [[13,10],[50,27]] 0.702 [0.272, 1.812] / 0.472 | 0.928 [0.433, 1.991] / 0.848 | 0.43 |
| ghsa | any | 142 | [[20,17],[40,65]] | 1.912 [0.897, 4.076] | 0.121 | [[7,7],[6,22]] 3.667 [0.920, 14.617] / 0.082 | [[13,10],[34,43]] 1.644 [0.643, 4.205] / 0.346 | 2.104 [0.971, 4.558] / 0.057 | 0.42 |
| ghsa | ghsa | 142 | [[20,17],[40,65]] | 1.912 [0.897, 4.076] | 0.121 | [[7,7],[6,22]] 3.667 [0.920, 14.617] / 0.082 | [[13,10],[34,43]] 1.644 [0.643, 4.205] / 0.346 | 2.104 [0.971, 4.558] / 0.057 | 0.42 |
| ghsa | osv | 142 | [[20,17],[40,65]] | 1.912 [0.897, 4.076] | 0.121 | [[7,7],[6,22]] 3.667 [0.920, 14.617] / 0.082 | [[13,10],[34,43]] 1.644 [0.643, 4.205] / 0.346 | 2.104 [0.971, 4.558] / 0.057 | 0.42 |
| osv | any | 142 | [[20,17],[61,44]] | 0.849 [0.399, 1.803] | 0.702 | [[7,7],[11,17]] 1.545 [0.424, 5.633] / 0.530 | [[13,10],[50,27]] 0.702 [0.272, 1.812] / 0.472 | 0.928 [0.433, 1.991] / 0.848 | 0.43 |
| osv | ghsa | 142 | [[20,17],[61,44]] | 0.849 [0.399, 1.803] | 0.702 | [[7,7],[11,17]] 1.545 [0.424, 5.633] / 0.530 | [[13,10],[50,27]] 0.702 [0.272, 1.812] / 0.472 | 0.928 [0.433, 1.991] / 0.848 | 0.43 |
| osv | osv | 142 | [[20,17],[61,44]] | 0.849 [0.399, 1.803] | 0.702 | [[7,7],[11,17]] 1.545 [0.424, 5.633] / 0.530 | [[13,10],[50,27]] 0.702 [0.272, 1.812] / 0.472 | 0.928 [0.433, 1.991] / 0.848 | 0.43 |

**Grouping has no effect in this snapshot.** GHSA and OSV give identical campaign signatures for only 87/200 packages, yet both partitions are the same: 140 singletons, 1×15, 1×45 (checked member-by-member). Every grouping text was confirmed to come from the requested source (142/142 representatives have `source == group_on`). All the variation comes from the DV text. any ≡ osv because OSV is positive whenever GHSA is: package-level (GHSA+, OSV+) counts are (T,T) 104, (F,F) 75, (F,T) 21, (T,F) 0.

**The 21 OSV-positive / GHSA-negative packages.** This is 21, not A2's 20: `memoryos` is added once the duplicate OSV record is kept. 16 are PyPI and 5 npm. **0/21 are grammar-flagged, vs 37/179 among the rest (Fisher p = 0.016;** A2 reported 0/20, p = 0.029). Hand reading of each OSV match (one reader, not a validated annotation; the per-package listing with matched_text was produced with `select_canonical_record(..., "ghsa"/"osv")` over the labeled snapshot and is not saved as a file):

| Pattern | Packages | Detail |
|---|---|---|
| OSV text carries an **amazon-inspector** section that the GHSA text lacks, and every match lies in that section | 19 | GHSA text = kam193 section only (14: vercel-runtime-python, prosocks, memoryos, auclean, starlette-healthchecks, aiosendletter, rak-lab-yoav-orca-zrktd2cp5hjmo4x7, trongappy, licloud, trongridew, proxycer, metricboxlite, trongridi, gcphelpit) or GHSA generic boilerplate (5 npm: homestack-cheer, pf25262, pflag14570, pf25133, ddok-modal) |
| Same, plus one match in the OSV preamble | 1 | tsshare (GHSA text is a 306-char one-liner) |
| OSV text carries a **kam193** section that the GHSA text lacks | 1 | timeweave (GHSA = amazon-inspector only; match = kam193's "Downloads and executes a remote executable") |

Across the 200 packages, 85 have an OSV reporter section absent from GHSA. All 21 disagreements fall in that set, and none occur outside it. Reading the matches: in all 21 the OSV text does describe a concrete mechanism, e.g. "POSTs the caller-supplied Tron private key as JSON to the hardcoded endpoint", "reads the DEPLOYMENT_TOKEN environment variable and POSTs it", "base64-decodes it, marshal.loads … exec(", "custom install command writes prosocks.bat into the Windows Startup folder". So the binary DV looks correct on the OSV text. Category assignment is off in 5: host-reconnaissance beacons (vercel-runtime-python, starlette-healthchecks, licloud, metricboxlite) are labelled `credential_or_wallet_exfiltration`, and an inline base64 second stage (homestack-cheer) is labelled `remote_payload_retrieval`. 15 of the 33 matches involve the `POST… hardcoded/endpoint/webhook` pattern that review B4 calls loose; in these 21 texts it fired on genuine exfiltration/beacon descriptions.

**Interpretation.** A2 hypothesised that the disagreements are a labeler artifact (longer OSV text → more regex surface), which would make the GHSA-only row more trustworthy. The reading above does **not** support that: the OSV matches are true mechanism descriptions. The disagreement is a **reporter-coverage** effect: the OSV record concatenates more reporters' write-ups (mostly amazon-inspector) than the GHSA record. That makes this the A3 confounder in another form. The GHSA-only row (OR 1.912 [0.897, 4.076], p 0.121; CMH 2.104 [0.971, 4.558], p 0.057) does not measure the malware "more cleanly". It measures it with one reporter's text removed, and that reporter's extra detail went disproportionately to non-flagged packages (0/21 flagged). Neither row is significant at 0.05; the point estimate crosses 1 depending on the DV text, as A2 said.

**Open decision (not taken here).** Which text is canonical is a research choice and is left open. Options: (a) GHSA, as primary source, with OSV as sensitivity; (b) OSV, as the superset of reporter text; (c) the D2 route, i.e. parse reporter sections and model reporter explicitly, which this result argues for. Nothing in this section changes 5.6's numbers; the defaults still reproduce them.

**D1 decision (2026-10-03).** The open decision above is now taken:
- **Canonical DV text = union of all sources (`--text-source any`)**, i.e. the 5.6 setting, which stays the headline row (OR 0.849 [0.399, 1.803], p 0.702; CMH 0.928 [0.433, 1.991], p 0.848).
- Reason: the 21 OSV-only positives are real mechanism descriptions from reporter sections (almost all amazon-inspector) that the GHSA record omits. Of the 21, **20 are clear** mechanism descriptions and **1 is borderline**: timeweave, whose only matches are the kam193 scanner-template reason line "Downloads and executes a remote executable". Match sections: amazon-inspector 30/33, kam193 2/33 (timeweave), OSV preamble 1/33 (tsshare). Dropping that text would discard true positives, not labeler noise.
- **GHSA-only (`--text-source ghsa`) is reported as a sensitivity row** (OR 1.912 [0.897, 4.076], p 0.121; CMH 2.104 [0.971, 4.558], p 0.057). It is not a candidate headline.
- The A2 instability (OR crossing 1 by DV text) is therefore a **reporter-coverage effect**, i.e. an instance of A3, and is taken up in D2 (Section 5.10).
- The per-package and per-match snippet table (21 packages, 33 matches, D1 call per package, the 5 category-assignment notes) is saved as `reports/osv_only_positives.md`, as annotation material for D4.

### 5.10 Reporter as a covariate (review.md A3 / D2)

**Code.**
- `src/data/incident_clients.py`: `extract_reporters(text)` returns every `## Source: <name>` header in order, with the hex digest suffix stripped and repeats kept. It appends `<ghsa-boilerplate>` if the "should be considered fully compromised" template is present. Non-empty text with neither returns `["<unattributed>"]`, and empty text returns `[]`. Also added: `union_reporters()` (order-preserving union) and `count_reporters()`.
- `src/statistics/h1_pilot_analysis.py`: `attach_grammar_labels()` attaches `reporters` and `n_reporters`. `reporters` is the union over **all** of a package's records from both sources, keyed by (ecosystem, package_name). Both collapse stages union `reporters`: at name level over all members, whatever `text_source` is, and at campaign level over names. New: `reporter_indicators()`, `n_reporters_stratum()`, `add_reporter_covariates()`, `rates_by_indicator()`, `fit_reporter_logistic_regression()` (statsmodels Logit, Wald 95% CIs). `build_campaign_signature()` now reads the boilerplate phrase from the shared constant. The string is unchanged.
- `run_check.py`: new section 6 prints (a)–(d) below and writes them to the results JSON under `reporters_d2`. Sections 0–5 are unchanged, and the defaults still reproduce 5.6 (142 campaigns, [[20,17],[61,44]], OR 0.849, p 0.702, CMH 0.928 / 0.848).
- `requirements.txt`: `statsmodels>=0.14` (0.15.0 installed).
- Tests: 15 new (7 in `test_incident_clients.py`, 8 in `test_h1_pilot_analysis.py`), including a snapshot test that pins the package-level `n_reporters` counts, the (a) tables and the 5.6 table. Suite: **125 passed** (was 110).

**Definitions (two deviations from the D2 design as first written, both agreed before implementation).**
1. Headerless, non-boilerplate text → `<unattributed>`. Without this, 73/200 packages (both texts headerless; 75 of their records end in "Credit: OpenSSF") would have `n_reporters = 0`, outside the 1 / 2+ strata.
2. OSV's `## Source: ghsa-malware` section is the GHSA boilerplate text. `reporters` keeps both strings, but `count_reporters()` counts `ghsa-malware` and `<ghsa-boilerplate>` as one reporter. Without this, 4 boilerplate-only packages would be in 2+ and 9 others would have n = 3.
- Indicators: `has_kam193`, `has_amazon_inspector`, `has_boilerplate` (either alias), `has_other` (any reporter outside {kam193, amazon-inspector, ghsa-malware, `<ghsa-boilerplate>`}, i.e. `<unattributed>` or `ossf-package-analysis`).
- Strata: n_reporters 1 vs 2+ (no campaign has 0).

**Coverage.** Package level (n = 200): n_reporters 1 = 114, 2 = 83, 3 = 3. Reporter sets: `<unattributed>` 73; {kam193, amazon-inspector} 72; amazon-inspector 20; kam193 16; {amazon-inspector, ghsa-malware, boilerplate} 9; {ghsa-malware, boilerplate} 4; {kam193, amazon-inspector, ossf-package-analysis} 2; {`<unattributed>`, amazon-inspector} 2; {kam193, amazon-inspector, `<unattributed>`} 1; ossf-package-analysis 1. Campaign level (n = 142): n_reporters 1 = 56, 2 = 83, 3 = 3. The two Baileys groups (45 and 15 names) are both `<unattributed>`.

All tables below use the default setting (`--text-source any --group-on any`). Table layout is [[flagged & DV+, flagged & DV−], [unflagged & DV+, unflagged & DV−]].

**(a) Campaign-level 2×2 and Fisher by n_reporters stratum**

| n_reporters | n | Table | OR | OR 95% CI | p |
|---|---|---|---|---|---|
| 1 | 56 | [[9,10],[11,26]] | 2.127 | [0.678, 6.676] | 0.244 |
| 2+ | 86 | [[11,7],[50,18]] | 0.566 | [0.190, 1.683] | 0.383 |

**(b) CMH**

| Stratified by | Strata | Common OR | OR 95% CI | χ² | p |
|---|---|---|---|---|---|
| n_reporters | 2 | 1.074 | [0.490, 2.354] | 0.034 | 0.854 |
| ecosystem × n_reporters | 4 | 0.979 | [0.438, 2.185] | 0.003 | 0.957 |

| Stratum (ecosystem × n_reporters) | n | Table |
|---|---|---|
| npm, 1 | 33 | [[7,7],[6,13]] |
| npm, 2+ | 9 | [[0,0],[5,4]] |
| pypi, 1 | 23 | [[2,3],[5,13]] |
| pypi, 2+ | 77 | [[11,7],[45,14]] |

**(c) Grammar-flag rate and DV rate by reporter indicator (campaign level)**

| Indicator | Value | n | Flagged | Flag rate | DV+ | DV rate |
|---|---|---|---|---|---|---|
| has_kam193 | True | 91 | 21 | 0.231 | 57 | 0.626 |
| has_kam193 | False | 51 | 16 | 0.314 | 24 | 0.471 |
| has_amazon_inspector | True | 106 | 27 | 0.255 | 65 | 0.613 |
| has_amazon_inspector | False | 36 | 10 | 0.278 | 16 | 0.444 |
| has_other | True | 21 | 9 | 0.429 | 17 | 0.810 |
| has_other | False | 121 | 28 | 0.231 | 64 | 0.529 |
| has_boilerplate | True | 13 | 0 | 0.000 | 5 | 0.385 |
| has_boilerplate | False | 129 | 37 | 0.287 | 76 | 0.589 |

**(d) Logistic regression** `dv ~ grammar_flag + C(ecosystem) + n_reporters + has_amazon_inspector`. n = 142 campaigns, converged, McFadden pseudo-R² 0.095, LLR p 0.0010. Reference ecosystem: npm. n_reporters enters as a count.

| Term | Coef | SE | z | p | OR | OR 95% CI |
|---|---|---|---|---|---|---|
| Intercept | −2.215 | 0.684 | −3.24 | 0.001 | 0.109 | [0.029, 0.417] |
| ecosystem = pypi | 0.012 | 0.460 | 0.03 | 0.979 | 1.012 | [0.411, 2.492] |
| grammar_flag | 0.081 | 0.426 | 0.19 | 0.848 | 1.085 | [0.471, 2.501] |
| n_reporters | 1.963 | 0.618 | 3.18 | 0.001 | 7.122 | [2.123, 23.893] |
| has_amazon_inspector | −0.934 | 0.619 | −1.51 | 0.131 | 0.393 | [0.117, 1.322] |

Reproduce: `python run_check.py` (section 6). Other text settings print the same section; e.g. `--text-source ghsa` gives (a) 1: [[9,10],[11,26]] OR 2.127 [0.678, 6.676] p 0.244, 2+: [[11,7],[29,39]] OR 2.113 [0.730, 6.115] p 0.191; (b) CMH by n_reporters OR 2.120 [0.973, 4.617] p 0.058, by ecosystem × n_reporters OR 1.792 [0.811, 3.961] p 0.151.

**(d) Sensitivity fits and VIFs** (added 2026-10-03; `run_check.py` section 6 (d) VIFs and (e)). Same n = 142 campaigns and default text setting. All four models include `C(ecosystem)`, and all converged. Coefficients are on the log-odds scale. CIs are 95% Wald.

| Model | Covariates besides grammar_flag + ecosystem | Term | Coef [95% CI] | OR [95% CI] | p |
|---|---|---|---|---|---|
| (d) original | n_reporters, has_amazon_inspector | grammar_flag | 0.081 [−0.754, 0.917] | 1.085 [0.471, 2.501] | 0.848 |
| | | n_reporters | 1.963 [0.753, 3.174] | 7.122 [2.123, 23.893] | 0.001 |
| | | has_amazon_inspector | −0.934 [−2.147, 0.279] | 0.393 [0.117, 1.322] | 0.131 |
| (a) drop has_amazon_inspector | n_reporters | grammar_flag | 0.019 [−0.796, 0.834] | 1.019 [0.451, 2.302] | 0.964 |
| | | n_reporters | 1.314 [0.513, 2.115] | 3.722 [1.670, 8.293] | 0.001 |
| (b) drop n_reporters | has_amazon_inspector | grammar_flag | −0.081 [−0.858, 0.695] | 0.922 [0.424, 2.004] | 0.837 |
| | | has_amazon_inspector | 0.483 [−0.321, 1.287] | 1.621 [0.726, 3.622] | 0.239 |
| (c) = (a) + has_boilerplate + has_kam193 | n_reporters, has_boilerplate, has_kam193 | grammar_flag | −0.246 [−1.099, 0.608] | 0.782 [0.333, 1.836] | 0.573 |
| | | n_reporters | 2.228 [1.063, 3.393] | 9.281 [2.896, 29.743] | <0.001 |
| | | has_boilerplate | −2.096 [−3.891, −0.301] | 0.123 [0.020, 0.740] | 0.022 |
| | | has_kam193 | −1.731 [−3.519, 0.056] | 0.177 [0.030, 1.058] | 0.058 |

VIFs for model (d): computed from the design matrix with the intercept included, and reported for the non-intercept columns.

| Column | VIF |
|---|---|
| ecosystem = pypi | 1.366 |
| grammar_flag | 1.017 |
| n_reporters | 2.415 |
| has_amazon_inspector | 1.957 |

With `--text-source ghsa`, model (c) does not converge (`converged=False` in the output). Every has_boilerplate campaign is DV− under GHSA text, so that column is completely separated. Models (d), (a) and (b) converge under that setting.

### 5.11 IV validation: naming grammar vs real hallucinations and popular benign names (review.md A1 / B2 / D3)

**Code.**
- `src/evaluation/grammar_validation.py` (new) runs `classify_naming_grammar` unchanged over three sets and writes `results/grammar_validation.json`. For each set, overall and per ecosystem, the output has n, flag count, flag rate, pattern_type distribution, top-15 flagging tokens (counted once per unit), and the flagged and unflagged hallucinated examples. Run with `python -m src.evaluation.grammar_validation`. The first run fetches the benign lists and caches them to `data/external/`, with manifests in `data/metadata/`. Later runs are offline. `--refresh` re-fetches.
- A campaign is flagged if any member name is, the same rule `collapse_to_campaign_level()` uses. The module checks campaign by campaign that its flag equals the pipeline's flag, and stops if they differ. They agree on all 142 (flagged 37, which matches the 5.6 table's 20 + 17).
- `src/data/seed_lists.py`: new `fetch_top_npm_names()` and `parse_npm_high_impact_top()`. These read the download-ranked list `npm-high-impact@1.13.0/lib/top.js` from jsDelivr (pinned version, 17,338 names; first 5,000 taken). `fetch_seed_npm_names()` is unchanged.
- **Why the npm benign source changed** (agreed before implementation): `fetch_seed_npm_names(5000)` returns the union of npm search results for 14 terms, 8 of which are grammar tokens (react, test, server, cli, api, core, plugin, client). That makes it a set selected on the IV. It also returned only 3,031 names on the first try and 2,593 on the cached run (3 of 14 terms failed), in arbitrary set order. It is kept below as a sensitivity row only.
- Tests: 11 in `tests/test_grammar_validation.py`, with fixture `tests/fixtures/hallucinated_tiny.txt`. Five more in `test_h1_pilot_analysis.py` cover the 5.10(d) sensitivity fits, the VIFs and the OR CIs. One test pins the real hallucinated rates. Suite: **141 passed**.
- OR CIs: `run_fisher_exact()` now also returns `odds_ratio_ci_95`, a Woolf interval from statsmodels `Table2x2`. It is `None` when a cell is zero, because no continuity correction is applied. `run_cmh_test()` returns `common_odds_ratio_ci_95` (Robins-Breslow-Greenland, statsmodels `StratifiedTable`). `run_check.py` prints both. The point estimates and p-values are unchanged, and the defaults reproduce 5.6. The CIs were added to the OR tables in 5.6, 5.9 and 5.10.

**Inputs.**
- Hallucinated: `data/external/hallucinated_names.txt`, the "universal" set (hallucinated by all five models) of Churilov 2026, arXiv:2605.17062, CC-BY-4.0. Provenance is in `hallucinated_names_SOURCES.md`.
- Benign PyPI: hugovk top-pypi-packages (list dated 2026-10-01 12:40:51), top 5,000.
- Benign npm: npm-high-impact 1.13.0, top 5,000.
- Malware: the 142 default campaigns of 5.6.
- Benign lists fetched 2026-10-03.

**Validation table.** Rates have Wilson 95% CIs.

| Set | Ecosystem | n | Flagged | Flag rate [95% CI] | none / compound / trend / both |
|---|---|---|---|---|---|
| Hallucinated | PyPI | 121 | 4 | 0.033 [0.013, 0.082] | 117 / 4 / 0 / 0 |
| Hallucinated | npm | 18 | 3 | 0.167 [0.058, 0.392] | 15 / 3 / 0 / 0 |
| Hallucinated | all | 139 | 7 | 0.050 [0.025, 0.100] | 132 / 7 / 0 / 0 |
| Benign top-5000 | PyPI | 5,000 | 821 | 0.164 [0.154, 0.175] | 4,179 / 792 / 17 / 12 |
| Benign top-5000 | npm | 5,000 | 1,031 | 0.206 [0.195, 0.218] | 3,969 / 1,011 / 9 / 11 |
| Benign top-5000 | all | 10,000 | 1,852 | 0.185 [0.178, 0.193] | 8,148 / 1,803 / 26 / 23 |
| Malware campaigns | PyPI | 100 | 23 | 0.230 [0.158, 0.322] | 77 / 22 / 0 / 1 |
| Malware campaigns | npm | 42 | 14 | 0.333 [0.210, 0.484] | 28 / 11 / 3 / 0 |
| Malware campaigns | all | 142 | 37 | 0.261 [0.195, 0.338] | 105 / 33 / 3 / 1 |
| *Sensitivity: npm search-API set* | npm | 2,593 | 1,898 | 0.732 [0.715, 0.749] | 695 / 1,882 / 2 / 14 |

**Top flagging tokens** (units containing the token):
- Hallucinated: aws 2; api, flask, plugin, react, language 1 each.
- Benign PyPI: azure 161, google 107, django 107, cloud 85, core 64, py 60, client 54, sdk 52, api 39, flask 36, aws 33, cli 23, ai 22, dagster 19, plugin 17.
- Benign npm: react 242, plugin 234, core 110, node 94, sdk 83, aws 77, utils 60, client 41, extension 39, config 37, cli 31, tools 29, vue 24, azure 19, api 17.
- Malware campaigns: py 8, tools 5, ai 4, client 4, utils 3, test 3, sdk 2, cli 2, dev 2; azure, core, cloud, config, react 1 each.

**Flagged hallucinated names (7/139)** (name, hallucination count, matched token):

| Ecosystem | Name | Count | Token |
|---|---|---|---|
| PyPI | aws-cdk | 429 | aws |
| PyPI | simics-6-api | 5 | api |
| PyPI | flask-idempotency | 5 | flask |
| PyPI | aws-retry | 5 | aws |
| npm | rollup-plugin-es6 | 5 | plugin |
| npm | react-randomized | 5 | react |
| npm | iana-language-tag | 5 | language |

**Unflagged hallucinated names: the 15 with the highest counts** (132 unflagged in all): objc 375, opentelemetry 374, rest-framework 315, tencentcloud 215, mpl-toolkits 117, opengl 103, openstack 102, git 91, android 62, @ember/service 55 (npm), ruamel 53, @ember/object 53 (npm), openssl 45, pyobjctools 40, dbus 33. Other unflagged names include win32com, win32api, rospy, skfuzzy, sklearnex and urllib2.

**Decision (2026-10-03).** "The hallucination framing is dropped. The IV is reported as compound/generic naming. Real hallucinations in these data are predominantly import/module names used as package names, orthogonal to compound-token structure."

### 5.12 Labeler spot-check sheet (review.md B4 / D4)

**Code.**
- `src/evaluation/labeler_spot_check.py` (new) writes `reports/labeler_spot_check.md` (the annotation sheet) and `results/spot_check_sample.json` (seed, frame sizes, the 51 package names, per-row advisory ids and categories). Run with `python -m src.evaluation.labeler_spot_check`. Patterns, token lists and the snapshot are unchanged. The script calls `label_text()` again on the same combined summary + description text only to print 100 characters of context instead of 80.
- Tests: 4 in `tests/test_labeler_spot_check.py` (snippet format, seeded draw is deterministic, error when n is larger than the frame, row counts on the frozen snapshot). Suite: **145 passed**. `run_check.py` still reproduces 5.6: [[20,17],[61,44]], OR 0.849, p 0.702.

**Sample.**
- (a) The 21 OSV-only positives (5.9), in the order of `reports/osv_only_positives.md`. The script recomputes the set from the snapshot and stops if it differs from that report. 33 matches, the same as the report.
- (b) Frame: the 81 DV-positive campaigns of the 142 any/any campaigns, minus the 21 packages in (a). None of the 21 is in a multi-name campaign. That leaves **60 campaigns: 13 npm, 47 PyPI**. The request was 15 npm + 15 PyPI. Fifteen npm cannot be drawn from 13, so the decision (2026-10-04) was **all 13 npm (census) + 17 PyPI**, sampled with `random.Random(42).sample` over the PyPI frame sorted by package name. Total: 51 rows, 30 in (b), 94 matches in (b).
- PyPI draw: aitextkit-py, aitextutils-py, bfox-build-utils, bq-build-probe-vrp-2026, bq-sdist-probe-vrp, caracas4check, donutautosellsrc, donutpromotion, env-validator-tool, eth-account-web3, faiss-cpu-avx512, pullgetsage, pymem-win, requests-triwes, tego-managed-agents-test, telemetry-helper, uvhttp-custom.
- One row in (b) is the 45-name Baileys campaign. Its row is `levvleys`, the first member name with a positive record.

**Rows per matched category** (a row counts once per category):

| Category | (a) n=21 | (b) n=30 |
|---|---|---|
| credential_or_wallet_exfiltration | 17 | 9 |
| hidden_install_hook | 1 | 13 |
| remote_payload_retrieval | 2 | 8 |
| remote_backdoor_access | 1 | 4 |
| obfuscated_payload_execution | 1 | 3 |
| brand_impersonation_narrative | 2 | 2 |

In (b), 11 of the 13 npm rows match `hidden_install_hook` and no other category.

**Caveats for the annotators.**
- The sheet shows package names, as requested. `annotation_guidelines.md` (written for the injection taxonomy) says to hide names. With names visible, verdicts should not be used for any analysis that conditions on the grammar flag.
- npm in (b) is a census, not a sample. Precision estimates for the npm stratum have no sampling error with respect to this frame, and they cover only 13 campaigns.
- No verdicts filled in yet.

### 5.13 Labeler negation filter and "## Source:" header strip (from the 5.12 sheet). Supersedes 5.6

Two bugs found by reading `reports/labeler_spot_check.md`. Snapshot, regex patterns and token lists are unchanged.

**Fix 1: negation (`src/labeling/malware_labeler.py`).** Sheet row 31 (levvleys, GHSA-9q97-jr9x-2qfr) was DV-positive because of the text "it does not exfiltrate credentials, establish persistence, or execute arbitrary remote code". Its two matches were credential_or_wallet_exfiltration and remote_backdoor_access. `label_text()` now drops a match when the 40 characters before it contain a cue from: does not, do not, did not, doesn't, no evidence of, without, rather than (whole words, case-insensitive; `is_negated()`, `NEGATION_CUES`, `NEGATION_WINDOW`).
- Matches dropped across the 401 records: **182**. 180 are the levvleys sentence, repeated in the GHSA and OSV records of all 45 packages in the 45-name Baileys campaign (2 matches × 90 records). The other 2 come from py-venv-doctor (GHSA-94w6-hr49-qjm7), where the cue fires wrongly: "the author **did not** have malicious intentions, but exfiltrating all environment variables…". That is a true mechanism being dropped. The record stays DV-positive because of its other matches, so no DV changes. This is a **known false negation of the 40-character window**.
- Records whose DV changes: **90 of 401**, all true → false (record DV+ 229 → 139). These are the GHSA and OSV records of the 45 Baileys packages.
- Campaigns whose DV changes: **1 of 142** (levvleys, 45 names). Campaign DV+ 81 → 80.
- The 15-name Baileys group (danz-bails, "PhantomSub") does **not** flip. It had no regex-positive record before the fix (DV false), and it has none after. Both Baileys groups are now DV-negative.

**Fix 2: campaign signature (`build_campaign_signature()` in `h1_pilot_analysis.py`).** Lines matching `^## Source: …` are removed before the 200-character prefix is taken (`SOURCE_HEADER_LINE`). The GHSA-boilerplate check still runs on the unstripped text.
- **The fix does not merge the rows that motivated it.** Sheet rows 23–28, 30 and 32–34 are the 10 "amel10" dependency-confusion packages (ai-workshop-*, apl-rive-renderer, okra-cloud-cdk, …). Rows 29 (com.epi.e2e_test) and 31 (levvleys) use different texts. None of the 10 amel10 descriptions has a `## Source:` header. GHSA and OSV texts both **begin with the package name** ("ai-workshop-maa15-radio is a dependency-confusion package…"), so each 200-character prefix is unique. npm campaign count: **42 → 42**.
- Diagnostic only, not adopted: replacing the package name in the text with `<PKG>` merges the 10 amel10 packages, plus 10 + 3 Epic-style `mms-*` / `*-egs-*` packages (npm 42 → 22, total 89, pooled [[15,8],[39,27]]). The substitution is a plain substring replace, so it also splits groups (e.g. `urc` occurs inside "source"). It needs a token-aware version and a decision before use.
- What the strip does merge (any/any): 12 new PyPI groups, 36 fewer campaigns. 11 groups share a single kam193 `Campaign:` field: 2026-09-sherpy (2), 2026-09-donutautosellsrc (5), 2026-09-snap-queue (3), 2026-09-requests-triwes (2), 2026-09-pyjstat-smooth (2), 2025-04-tronix (3), 2026-09-openaii (4), 2026-09-web3-eth-account (2), 2026-09-amirgo4496 (3), 2026-09-asti (3), 2026-09-0requests (4). **The 12th is a 15-name group whose shared field is `GENERIC-standard-pypi-install-pentest`.** That is kam193's catch-all template ("Installing the package or importing the module exfiltrates basic information about the host…"), the same situation as the GHSA boilerplate exclusion. It is probably a false merge. Not changed here. Treating it like the boilerplate would give 120 campaigns.

| Campaign count | before | after |
|---|---|---|
| group_on any (= ghsa) — pooled | 142 | **106** |
| — npm | 42 | 42 |
| — PyPI | 100 | 64 |
| group_on osv — pooled | 142 | 137 (npm 42, PyPI 95) |

**Section 5.6 vs 5.13 (any/any, frozen snapshot, `python run_check.py`):**

| Stratum | 5.6 n | 5.6 table | 5.6 OR [95% CI] | 5.6 p | 5.13 n | 5.13 table | 5.13 OR [95% CI] | 5.13 p |
|---|---|---|---|---|---|---|---|---|
| Pooled | 142 | [[20,17],[61,44]] | 0.849 [0.399, 1.803] | 0.702 | 106 | [[19,12],[43,32]] | **1.178** [0.501, 2.772] | **0.829** |
| npm | 42 | [[7,7],[11,17]] | 1.545 [0.424, 5.633] | 0.530 | 42 | [[7,7],[10,18]] | 1.800 [0.490, 6.618] | 0.508 |
| PyPI | 100 | [[13,10],[50,27]] | 0.702 [0.272, 1.812] | 0.472 | 64 | [[12,5],[33,14]] | 1.018 [0.302, 3.436] | 1.000 |
| CMH | 142 | — | 0.928 [0.433, 1.991] | 0.848 | 106 | — | 1.325 [0.543, 3.233] | 0.535 |

Each fix applied alone (pooled): negation only, n=142, [[20,17],[60,45]], OR 0.882, p 0.848 (CMH 0.976, p 0.951). Strip only, n=106, [[19,12],[44,31]], OR 1.116, p 0.831 (CMH 1.237, p 0.639). The pooled OR crosses 1 because of the strip, which removes 36 PyPI campaigns.

**Other settings under 5.13:** GHSA text with GHSA grouping, n=106, [[18,13],[27,48]], **OR 2.462, p 0.052**. (The review.md A2 analogue at n=142 was OR 1.91, p 0.12.) OSV/OSV: n=137, [[20,17],[59,41]], OR 0.818, p 0.698. Power at n=106 for OR 2.0: 0.36 (0.43 at n=142).

**Reporter block (5.10) under 5.13:** CMH by n_reporters OR 1.683 [0.658, 4.305], p 0.267 (was 1.074, p 0.854). Logit `dv ~ grammar_flag + C(ecosystem) + n_reporters + has_amazon_inspector`, n=106: grammar_flag OR 2.013 [0.698, 5.804], p 0.195 (was 1.085, p 0.848); n_reporters OR 12.823, p <0.001; has_amazon_inspector OR 0.234, p 0.035.

**Reproduction target.** `run_check.py` no longer reproduces 5.6, by design. Both fixes correct measurement errors in 5.6. The new target is the 5.13 row above (pooled OR 1.178, p 0.829), and `CLAUDE.md` and the `(log …)` labels printed by `run_check.py` were updated to it. The `--group-on` / `--text-source` help strings still call any/any "the Section 5.6 behaviour"; that names the setting, not the numbers.

**Spot-check sheet regenerated** (seed 42). The npm frame is now 12, because levvleys is DV-negative, and the PyPI frame is 33 (was 13 / 47). Following the 2026-10-04 rule (npm census, PyPI fills part (b) to 30): **12 npm + 18 PyPI**, still 51 rows. Part (a) is unchanged (the same 21 packages, 33 matches). Part (b) has 99 matches (was 94). Part (a) `campaign_size` is now read from the campaigns instead of being fixed at 1. Changes:
- Removed: row 31 levvleys. Its matches were the negated sentence.
- Part (a) campaign size 1 → 15: licloud (9), metricboxlite (11), vercel-runtime-python (21), all in the GENERIC-pentest group. Size 1 → 3: trongappy, trongridew, trongridi (17–19).
- PyPI in (b) out: bq-sdist-probe-vrp, donutautosellsrc, donutpromotion, env-validator-tool, eth-account-web3, faiss-cpu-avx512, pymem-win, requests-triwes, tego-managed-agents-test. In: aseitylab, chroma-client, company-sdk, houdus, praetorian-mind-rce-test-2026, pylever, requests-auroras, rrs, web3-eth-account, websetup. Three of the "in" rows are the same campaign as an "out" row, shown under a different first member name: aseitylab ⊃ donutpromotion, requests-auroras ⊃ requests-triwes, web3-eth-account ⊃ eth-account-web3. donutautosellsrc is gone because its campaign merged into the aseitylab group.
- Numbering: npm rows 32–34 become 31–33. PyPI rows start at 34 (was 35) and are re-sorted alphabetically with the new draw.
- Rows per category in (b): hidden_install_hook 12, credential_or_wallet_exfiltration 11, remote_payload_retrieval 8, remote_backdoor_access 5, obfuscated_payload_execution 3, brand_impersonation_narrative 0.

**Tests.** New: `test_negated_mechanisms_in_levvleys_text_are_dropped`, `test_same_mechanisms_without_negation_still_match` and `test_negation_cues_and_40_char_window` (exact levvleys text). `test_build_campaign_signature_strips_source_header_lines` (exact shortneer / sherpy GHSA openings, different hashes) and `test_build_campaign_signature_strips_every_source_header_line`. Updated to 5.13 numbers: `test_default_settings_reproduce_section_5_6_and_any_group_equals_ghsa`, `test_snapshot_reporter_counts_section_5_10`, `test_spot_check_rows_on_frozen_snapshot`. Suite: **150 passed**.

**Open.** (1) The amel10 family (10 npm names, one campaign) is still 10 units. It needs a name-masking signature. (2) The GENERIC-pentest 15-name merge probably needs the boilerplate treatment. (3) py-venv-doctor shows that "did not" in a concessive clause is a false negation; a narrower cue or a clause-boundary check would fix it. All three change n or the DV, so each needs a decision first.

### 5.14 Campaign signature (Campaign tag, GENERIC exclusion, name mask) and narrowed negation. Supersedes 5.13

Four changes. Each one closes an item from the 5.13 "Open" list or the request that followed it. Snapshot, regex patterns and token lists are unchanged. Diagnostics: `python -m src.evaluation.signature_diagnostics` (new, read-only).

**Code.**
- `build_campaign_signature()` (`h1_pilot_analysis.py`) checks keys in this order:
  1. A specific kam193 `Campaign: <id>` line → `(ecosystem, "__campaign__:<id>")`. Switch: `use_campaign_tag`.
  2. The GHSA "fully compromised" boilerplate, or a record whose only Campaign tag is `GENERIC-standard-pypi-install-pentest` → per-package signature, as for the boilerplate. Switch: `exclude_generic_tag`. No record in the snapshot carries both the boilerplate and a specific tag.
  3. Otherwise the 200-character prefix, after the `## Source:` strip, with the record's own package name replaced by `<PKG>`. Switch: `mask_package_name`. `mask_name()` matches the name case-insensitively, and only when the character before it and the character after it are not in `[A-Za-z0-9_.@/-]`.
- All three switches default to on. With all three off, the partition is identical to 5.13 (checked group by group against a saved 5.13 baseline, and asserted in a test: n 106, [[19,12],[43,32]]). `collapse_to_campaign_level(**signature_options)` passes the switches through.
- Negation (`malware_labeler.py`): `without` and `rather than` were removed from `NEGATION_CUES`. A cue no longer suppresses a match when `but`, `;` or `.` occurs between the cue and the match (`NEGATION_BREAK`). New function: `negation_cue()` returns the cue that suppresses a match. `is_negated()` wraps it.
- `labeler_spot_check.py` now builds its frame with `SHEET_SIGNATURE_OPTIONS` (all three switches off). Under 5.14 grouping the npm frame drops from 12 to 3 campaigns. Redrawing would renumber the sheet. With the pin, the regenerated sheet is byte-identical to the current `reports/labeler_spot_check.md`. py-venv-doctor is not on the sheet, so the negation change does not touch it.

**Negation: match drops per cue, all 401 records** (5.13 credits the first cue in the window):

| Cue | 5.13 | 5.14 |
|---|---|---|
| does not | 180 | 180 |
| did not | 2 | 0 |
| without | 0 | 0 |
| rather than | 0 | 0 |
| total | 182 | 180 |

- py-venv-doctor: GHSA-94w6-hr49-qjm7 matches go 1 → 2 and MAL-2026-16296 matches go 2 → 3. The "did not … , but exfiltrating" match is kept.
- levvleys still loses both matches (both credited to `does not`).
- `without` and `rather than` dropped no matches in 5.13 either, so removing them changes nothing on this snapshot.
- Record DV changes from the negation change: **0 of 401**. Campaign DV changes: 0. The negation change has no effect on any table below.

**Campaign counts (text any, group any):**

| Signature setting | pooled | npm | PyPI |
|---|---|---|---|
| 5.13 (all off) | 106 | 42 | 64 |
| GENERIC exclusion only | 120 | 42 | 78 |
| Campaign tag only | 100 | 42 | 58 |
| Name mask only | 86 | 22 | 64 |
| Prefix: GENERIC exclusion + mask, no tag | 100 | 22 | 78 |
| **5.14 (all on)** | **94** | **22** | **72** |
| 5.14, group_on osv | 91 | 21 | 70 |

**(1) GENERIC exclusion.** The 15-name group from 5.13 is split into 15 singletons: licloud, metricboxlite, vercel-runtime-python, urc, azure-langchain-example, cloushaar-poc-exfil-91827, … This is the only group of the 5.13 partition that is split in 5.14.

**(2) Campaign tag vs text prefix** (both with the GENERIC exclusion and the mask):
- The tag merges 6 campaigns that the prefix did not. That is 12 prefix groups becoming 6. In every pair, the package texts share a Campaign id but differ within their first 200 characters after masking. dedh-devops-automation and spo365-graph have the same first 90 characters.
  - dedh-devops-automation + spo365-graph (2026-10-spo365-graph)
  - friendly-tools + friendly-greeting-tools (2026-09-friendly-greeting-tools)
  - aseity group (5) + donutautosellsrc (2026-09-donutautosellsrc)
  - langgrap group (4) + chroma-client (2026-09-openaii)
  - aitextkit-py + aitextutils-py (2026-09-aitextkit-py)
  - telemetry-helper + env-validator-tool (2026-09-telemetry-helper)
- The prefix merges **0** campaigns that the tag did not.

**(3) Name mask.**
- The 10 amel10 packages are now **one** campaign: ai-workshop-maa15-radio, ai-workshop-radio-app, ai-workshop-radio-lambda, alexa-cybertron-team-code-review-agent, apl-rive-renderer, brioche-apl-dev-env, figma-to-apl, live-detection-dashboard, niksinnkatalapp, okra-cloud-cdk. These are the names whose GHSA text names the account amel10.
- The mask also merges two Epic-style families. The first has 10 names: set-egs-backend, qa-egs-rollback, mms-service, mms-tools, … The second has 3: mms-ref-dedserver, mms-ref-client, generator-epic-react. Both are the same merges as the 5.13 substring diagnostic. They were not hand-checked as single actors. The two Epic groups stay separate from each other.
- Groups split by the mask: **0** (mask alone vs 5.13, and 5.14 vs 5.14 without the mask). Case-insensitive matching changes 3 OSV texts (memoryos, pymem-win, metricboxlite) and leaves the partition unchanged.

**Results, text any / group any (default; `python run_check.py`).**

| Stratum | n | table | OR [95% CI] | p |
|---|---|---|---|---|
| Pooled (Fisher) | 94 | [[13,12],[38,31]] | **0.884** [0.353, 2.211] | **0.818** |
| npm | 22 | [[3,3],[5,11]] | 2.200 [0.323, 14.975] | 0.624 |
| PyPI | 72 | [[10,9],[33,20]] | 0.673 [0.234, 1.940] | 0.587 |
| CMH by ecosystem | 94 | — | 0.890 [0.355, 2.232] | 0.802 |
| n_reporters = 1 | 32 | [[5,6],[4,17]] | 3.542 [0.707, 17.734] | 0.213 |
| n_reporters = 2+ | 62 | [[8,6],[34,14]] | 0.549 [0.161, 1.874] | 0.349 |
| CMH by n_reporters | 94 | — | 1.105 [0.426, 2.863] | 0.831 (χ² 0.046) |
| CMH by ecosystem × n_reporters | 94 | — | 1.067 [0.402, 2.830] | 0.891 (χ² 0.019) |

Logit `dv ~ grammar_flag + C(ecosystem) + n_reporters + has_amazon_inspector`, n=94, converged, pseudo-R² 0.121, LLR p 0.0036:

| Term | coef | SE | p | OR [95% CI] |
|---|---|---|---|---|
| Intercept | −2.184 | 0.878 | 0.013 | 0.113 [0.020, 0.630] |
| C(ecosystem)[pypi] | 0.507 | 0.558 | 0.364 | 1.660 [0.556, 4.956] |
| grammar_flag | −0.092 | 0.518 | 0.858 | **0.912** [0.331, 2.515] |
| n_reporters | 0.622 | 0.643 | 0.334 | 1.862 [0.528, 6.568] |
| has_amazon_inspector | 1.220 | 0.804 | 0.129 | 3.388 [0.701, 16.372] |

- VIFs: 1.103, 1.009, 2.339, 2.293.
- grammar_flag OR in the sensitivity fits:
  - (a) drop amazon: 0.992 [0.360, 2.732], p 0.987.
  - (b) drop n_reporters: 0.855 [0.317, 2.310], p 0.758.
  - (c) + boilerplate + kam193: 0.827 [0.279, 2.448], p 0.731.

Power (Hsieh), any/any: p_control 0.551, flagged prevalence 0.266.

| OR | n for 80%, pooled | power at n=94 | power npm (n=22) | power PyPI (n=72) |
|---|---|---|---|---|
| 0.5 | 339 | 0.31 | 0.10 | 0.24 |
| 0.67 | 1014 | 0.13 | 0.06 | 0.11 |
| 1.5 | 989 | 0.14 | 0.06 | 0.11 |
| 2.0 | 339 | **0.31** | 0.10 | 0.24 |
| 3.0 | 135 | 0.65 | 0.19 | 0.51 |

**Results, text GHSA / group any (`python run_check.py --text-source ghsa`).** group_on any gives the same grouping as group_on ghsa (see the test).

| Stratum | n | table | OR [95% CI] | p |
|---|---|---|---|---|
| Pooled (Fisher) | 94 | [[13,12],[19,50]] | **2.851** [1.107, 7.341] | **0.047** |
| npm | 22 | [[3,3],[0,16]] | inf [undefined: zero cell] | 0.013 |
| PyPI | 72 | [[10,9],[19,34]] | 1.988 [0.688, 5.746] | 0.276 |
| CMH by ecosystem | 94 | — | 2.907 [1.110, 7.612] | 0.023 |
| n_reporters = 1 | 32 | [[5,6],[4,17]] | 3.542 [0.707, 17.734] | 0.213 |
| n_reporters = 2+ | 62 | [[8,6],[15,33]] | 2.933 [0.864, 9.954] | 0.116 |
| CMH by n_reporters | 94 | — | 3.141 [1.187, 8.311] | 0.020 (χ² 5.448) |
| CMH by ecosystem × n_reporters | 94 | — | 2.700 [0.997, 7.317] | 0.049 (χ² 3.883); npm\|2+ is [[0,0],[0,9]] |

Logit (same formula), n=94, converged, pseudo-R² 0.103, LLR p 0.0147:

| Term | coef | SE | p | OR [95% CI] |
|---|---|---|---|---|
| Intercept | −2.201 | 0.941 | 0.019 | 0.111 [0.018, 0.700] |
| C(ecosystem)[pypi] | 1.522 | 0.729 | 0.037 | 4.581 [1.097, 19.129] |
| grammar_flag | 1.129 | 0.511 | 0.027 | **3.092** [1.136, 8.415] |
| n_reporters | −0.433 | 0.633 | 0.494 | 0.648 [0.187, 2.243] |
| has_amazon_inspector | 0.902 | 0.815 | 0.269 | 2.464 [0.498, 12.182] |

- VIFs: 1.103, 1.009, 2.339, 2.293.
- grammar_flag OR in the sensitivity fits:
  - (a) drop amazon: 3.131 [1.158, 8.469], p 0.025.
  - (b) drop n_reporters: 3.135 [1.154, 8.517], p 0.025.
  - (c) + boilerplate + kam193: 2.410 [0.859, 6.759], p 0.095. **This fit did not converge.** has_boilerplate is quasi-separated: 0/13 boilerplate campaigns are DV+ under GHSA text, coef −22.8.
- Power: p_control 0.275, prevalence 0.266. Pooled power at n=94 is 0.26 for OR 2.0 and 0.56 for OR 3.0 (n for 80%: 420 at OR 2.0, 167 at OR 3.0). PyPI: 0.24 at OR 2.0. npm: undefined (p_control 0).

**Each change alone (pooled Fisher, new negation; the negation change itself moves nothing):**

| Setting | any/any n, table, OR, p | GHSA/any n, table, OR, p |
|---|---|---|
| 5.13 signature | 106, [[19,12],[43,32]], 1.178, 0.829 | 106, [[18,13],[27,48]], 2.462, 0.052 |
| + GENERIC only | 120, [[18,17],[46,39]], 0.898, 0.842 | 120, [[18,17],[27,58]], 2.275, 0.061 |
| + tag only | 100, [[18,11],[40,31]], 1.268, 0.660 | 100, [[17,12],[24,47]], 2.774, 0.027 |
| + mask only | 86, [[15,8],[38,25]], 1.234, 0.804 | 86, [[14,9],[22,41]], 2.899, 0.047 |
| 5.14 all | 94, [[13,12],[38,31]], 0.884, 0.818 | 94, [[13,12],[19,50]], 2.851, 0.047 |
| 5.14, group_on osv (text any) | 91, [[13,11],[37,30]], 0.958, 1.000 | — |

**Reading.**
- The default (any-source) estimate moves from 1.178 to 0.884. It has now crossed 1 three times under signature choices: 5.6 0.849 → 5.13 1.178 → 5.14 0.884. All three CIs span roughly 0.35–2.8.
- The GHSA-text estimate stays between 2.28 and 2.90 under every signature setting above. Its p is 0.027–0.061.
- The GHSA pooled p 0.047 should not be read as a finding:
  - It is one of many text × grouping × signature settings examined in 5.9–5.14 with no correction for multiple comparisons.
  - The npm stratum has a zero cell. GHSA text is DV-negative for 0/16 unflagged npm campaigns.
  - The model with boilerplate and kam193 terms did not converge and gives OR 2.410, p 0.095.
  - Reporter confounding (A3) is not resolved. Boilerplate campaigns are DV+ 0/13 under GHSA text and 5/13 under any-source text. Section 5.14 does not decompose the any-vs-GHSA gap by reporter.
- Power at n=94 for OR 2.0 is 0.31 (any) and 0.26 (GHSA).

**Tests.**
- New in `test_h1_pilot_analysis.py`:
  - `test_build_campaign_signature_excludes_kam193_generic_pentest_template` (verbatim licloud / metricboxlite GHSA openings).
  - `test_build_campaign_signature_groups_on_kam193_campaign_tag` (verbatim aitextkit-py / aitextutils-py).
  - `test_build_campaign_signature_masks_own_package_name_amel10` (verbatim figma-to-apl / ai-workshop-maa15-radio text).
  - `test_mask_name_is_boundary_aware` (includes the `urc` / "source" case from 5.13).
- New in `test_malware_labeler.py`:
  - `test_negation_does_not_cross_but_in_py_venv_doctor` (verbatim sentence).
  - `test_negation_does_not_cross_semicolon_or_period`.
  - `test_without_and_rather_than_are_not_negation_cues`.
  - `test_levvleys_still_loses_both_matches_and_cue_is_reported`.
- Updated:
  - `test_negation_cues_and_40_char_window`: cue list. The whole-word check now uses "did nothing".
  - `test_build_campaign_signature_strips_source_header_lines`: sherpy now keys on its Campaign tag, and the strip is checked with `use_campaign_tag=False`.
  - `test_group_on_changes_grouping_but_not_outcome_source`: the fixture texts "osv text a"/"b" became "one"/"two". With package names "a" and "b", the mask made the two texts equal.
  - Snapshot tests: 5.14 numbers, plus all-off = 5.13.
- Suite: **158 passed**.

**Reproduction target.** `run_check.py` no longer reproduces 5.13, by design. The new target is the any/any row above: n 94, [[13,12],[38,31]], OR 0.884, p 0.818. `CLAUDE.md` and the `(log …)` labels in `run_check.py` are updated. `results/power_campaign_level.json` and `results/power_campaign_level__text-ghsa__group-any.json` were rewritten. The other `results/power_campaign_level__*.json` files and `results/grammar_validation.json` (5.11, which also collapses campaigns) were **not** rerun and still reflect 5.13 grouping.

**Open.**
1. The two Epic-style mms/egs groups (10 and 3 names) were merged by the mask without a hand check of whether they are one actor, or two that should be one.
2. Whether the spot-check sheet should be redrawn under 5.14 grouping. The npm census would be 3 campaigns.
3. Rerun of 5.11 grammar_validation at campaign level.

### 5.15 Labeler spot-check verdicts (review.md B4 / D4)

**Input.** Verdict and Note as filled in on `reports/labeler_spot_check.md` (51 rows; the sheet as regenerated under 5.13 grouping: 21 in (a), 30 in (b) = 12 npm census + 18 PyPI, per `results/spot_check_sample.json`). Parsed into `results/spot_check_verdicts.json` (per row: verdict, note, matches with a `tag_line` flag; plus the summary numbers below). Patterns, token lists, the snapshot and the sheet are unchanged.

**Annotation rule.** Matches found only in analyst tag lists, not in prose, were counted FALSE.

**Counts.**

| Verdict | All n=51 | (a) n=21 | (b) n=30 |
|---|---|---|---|
| REAL | 44 | 18 | 26 |
| FALSE | 3 | 1 | 2 |
| UNSURE | 4 | 2 | 2 |

- FALSE: rows 16 `timeweave`, 40 `chroma-client`, 49 `uvhttp-custom`.
- UNSURE: rows 7 `auclean`, 10 `memoryos`, 38 `bq-build-probe-vrp-2026`, 41 `company-sdk`.

**Precision** (Wilson 95% CI, row level):
- Excluding UNSURE: 44/47 = **0.936**, CI [0.828, 0.978].
- UNSURE counted as FALSE: 44/51 = **0.863**, CI [0.743, 0.932].

**Tag lines.** A match is a tag-line match if, in the snapshot text (summary + description, whitespace collapsed), it lies after the `Reasons (based on the campaign):` header with no `---` separator in between.
- Rows whose only matches were tag lines: **3** (rows 16, 40, 49). All 3 are FALSE, so the 3 FALSE verdicts are exactly these rows.
- Rows with at least one tag-line match: 11 (16, 34, 35, 36, 39, 40, 41, 42, 46, 49, 50). The other 8 also have prose matches and are 7 REAL, 1 UNSURE.

**What FALSE measures.** The verdicts judge the matched evidence, not the advisory. Of the 3 FALSE rows, 2 have prose in the snapshot that describes the behaviour the regex did not match:
- `uvhttp-custom`: "download and silently execute an opaque, unsigned binary".
- `timeweave`: "downloads each entry's url to a temp directory ... executes the downloaded file via ctypes.windll.kernel32.WinExec" (amazon-inspector), and "downloaded to a location disguised as a system utility and executed" (kam193).
- `chroma-client`: no such prose. kam193 says the package "does not carry any malicious payload yet", and amazon-inspector describes a .pth file whose payload is `os.umask(0o022)` plus prompt-injection comments. Here the label itself is wrong.

So for those 2 rows the FALSE verdict reflects the labeler matching the wrong evidence, not the advisory lacking it. The precision above measures evidence-level correctness. As a measure of whether the DV label is correct, it is conservative by those 2 rows: 46/47 = 0.979, CI [0.889, 0.996] excluding UNSURE; 46/51 = 0.902, CI [0.790, 0.957] with UNSURE counted as FALSE. This is not a strict lower bound on label precision, because the REAL verdicts were made from 100-character snippets with package names visible.

**Notes containing "category:":** 0 (also 0 case-insensitive).

**Not done.** `run_check.py` and the analysis code were not touched; 5.14 numbers are unaffected.

### 5.16 Per-campaign CSV export (Data in Brief Section 3.2)

**Why.** The Data in Brief draft (`paper_dib/dib_main.tex`, Section 3.2) says `run_check.py` writes a per-campaign table to `results/`. Before this section it wrote only the aggregate JSON.

**Change.**
- `src/statistics/h1_pilot_analysis.py`:
  - `campaign_table_rows()` gives one row per campaign in collapse order.
  - `write_campaign_csv()` writes those rows.
  - `signature_type()` recovers which `build_campaign_signature()` rule keyed the campaign: `campaign_tag`, `own_package` (boilerplate or GENERIC tag) or `text_prefix`.
- `run_check.py` writes `results/campaigns.csv`. Non-default settings write `results/campaigns__text-<x>__group-<y>.csv`.
- Columns: `campaign_id` (C001.., collapse order), `ecosystem`, `member_packages` (`;`-separated), `signature_type`, `grammar_flag`, `mechanism_label`, `n_reporters`, `kam193`, `amazon_inspector`, `boilerplate`. Flags and indicators are 0/1.
- The collapse, labeler, grammar and snapshot are unchanged.

**Output (any/any).**
- 94 rows: 22 npm, 72 PyPI.
- 200 distinct member packages.
- grammar_flag 25, mechanism_label 51, flagged and positive 13. These match [[13,12],[38,31]].
- signature_type counts: campaign_tag 42, own_package 30, text_prefix 22.
- Largest campaigns have 45, 15, 10, 10, 6 and 5 packages.
- Mechanism rate by reporter indicator: amazon_inspector 46/71 vs 5/23 without it; boilerplate 5/13.

**Reproduction.**
- `run_check.py` still prints the 5.14 numbers: n 94, OR 0.884, p 0.818; CMH OR 0.890, p 0.802.
- `results/power_campaign_level.json` is byte-identical after the rerun.

**Tests.**
- `test_campaign_csv_rows_signature_types_flags_and_reporters` covers a synthetic fixture with one campaign per signature type, plus the CSV round-trip.
- `test_snapshot_campaign_csv_matches_section_5_14` pins the counts above on the frozen snapshot.
- Suite: **160 passed**.

**Note for the paper.** Section 3.4 of the draft calls 5/13 the rate for "boilerplate-only campaigns". 13 is the count of campaigns with *any* boilerplate reporter (`boilerplate` = 1). Campaigns whose only reporter is the boilerplate number 4, and all 4 are mechanism-negative (0/4).

---

## 6. Novelty / Literature Positioning

Checked via Consensus search against the current (2026) literature before proceeding further:

- **Package hallucination and slopsquatting as an attack surface:** established (Spracklen et al.; Huang et al., whose 35.2%-install-rate / two-week-window / \$496-campaign-cost figures anchor the problem statement).
- **Prompt injection targeting AI agents via skill/tool documentation:** established and now a fast-moving 2026 subfield (Spira et al.'s "HalluSquatting" — a live attack demonstration with up to 100% success and demonstrated RCE against production agents; Yuan et al.'s large-scale skill-hallucination measurement, which also found existing defenses carry a severe usability cost; Liu et al. and Hsu et al. on skill-level attack/evasion techniques).
- **What this project's actual corpus and finding address, and why it does not collide with the above:** the skill-hallucination literature concerns a different attack surface and mechanism (hallucinated *skill* names hosting adversarial *prompts* that manipulate an *agent*, versus this project's squatted *package* names shipping malicious *code* executed on install). This project's corpus is package-level, GHSA/OSV-sourced malware-behavior text, and its finding concerns attacker resource allocation across naming strategy and payload engineering **within conventional package squatting** — a question the skill-focused literature does not ask. A theoretical anchor for the finding's plausibility (predictable-name attacks being lower-effort across the board) comes from Allodi et al.'s "work-averse attacker" model from the vulnerability-exploitation literature, which found attackers systematically minimize fixed development costs. **This anchor is weaker after Section 5.5's correction**, since the corrected result is a null finding rather than the directional signal the Allodi et al. framing was originally invoked to explain — it may still motivate a hypothesized direction for a properly powered follow-up, but should not be cited as explaining an observed effect.
- A companion 2026 paper, Hillah et al., uses PyPI registration *metadata* (not documentation text) to catch suspicious-but-registered packages with a calibrated posterior — related but distinct (different signal, no naming-grammar-correlation claim).

A draft paper introduction incorporating this positioning has been written (`phantom_guard_introduction.md`, not reproduced in this log) — **flag for revision given Section 5.5's correction before further use.**

---

## 7. What Is Left To Do

Revised in light of Sections 5.5 and 5.8. In rough priority order:

1. **Grow the incident corpus** to ~350 independent campaigns (~1,000 raw records). The power-analysis half of this item is **DONE — see Section 5.8**: at n=142 the study has ~43% power for OR=2.0, so the null is uninformative and corpus growth is confirmed as the gate for everything below. Concretely: extend the GHSA pull beyond 5 pages (older advisories), and verify/add `pypa/malware-reports` per `config/base.yaml`. Rerun `run_check.py` after each growth step to track achieved power.
2. **Resolve the control-sample gap.** The 20-package external control sample was collected and validated but never used. Decide and implement: either (a) fold it into a matched-control design, or (b) explicitly justify the within-corpus-only comparison actually used and drop the external control sample from the pipeline. Unchanged by this session.
3. **Full logistic regression with controls**, per the original methodology: `malware_payload_present ~ grammar_match + ecosystem + package_age + popularity + doc_length`, run on campaign-level (not raw record-level) units now that `collapse_to_campaign_level()` exists. Blocked on item 1 — adding covariates raises the n requirement above the 5.8 floor.
4. **Freeze a single dataset snapshot for the FULL final analysis**, not just the one used for this session's debugging — Section 5.5's snapshot was frozen mid-correction and should be treated as a validation artifact, not necessarily the final corpus to report from. Re-pull fresh and re-freeze once the corpus-growth step (item 1) is done.
5. **Human validation of the malware labeler.** Still heuristic, not validated ground truth — now doubly important given the taxonomy changed materially (both the npm pattern additions and the boilerplate-pattern reversion). `reports/annotation_guidelines.md` exists (written for the earlier injection taxonomy, needs adaptation to the malware taxonomy) but no human-annotated sample or inter-annotator agreement has been produced yet. Note the post-patch record-level flag rates (npm 59.5%, PyPI 54.7%) are high enough that false positives are a live concern worth checking in the annotation sample.
6. **Bootstrap or exact confidence intervals** on the odds ratios, not just point estimates and p-values — particularly useful now given the null result, to characterize the range of effect sizes the data can rule out (5.8 gives the power-based version of this; a CI gives the data-based version).
7. **Matched-sample sensitivity analysis** (propensity-score or exact matching, as originally specified).
8. **Retrospective validation** (would this signal, if known in advance, have flagged real incidents before public disclosure) — not started; lower priority given the null result pending item 1.
9. **Reproducibility package**: license verification for GHSA/OSV redistribution terms (currently marked "not specified" in manifests), and a public release plan for the labeled corpus.
10. **Finish the paper**: related-work section (Section 6) needs the Allodi et al. framing softened per the note added there; results section needs to lead with the corrected null result (5.6/5.7) *and its power analysis (5.8)*, not the superseded first-round numbers (5.2–5.4); methods section should describe the two-stage campaign-collapse step as a required preprocessing step, not an afterthought.
11. ~~**Permanence step**~~ — **DONE, verified in Section 5.8.** The persisted `project_p0_edited` folder reproduces 5.6 exactly in a fresh local environment, and the code now runs with no Kaggle dependency (`pip install -r requirements.txt` → `pytest tests/` → `python run_check.py`).

---

## 8. Real Bugs Found and Fixed Along the Way

Documented here because each was a genuine, verified defect caught through actually running the code against real data — not hypothetical review comments.

1. **`get_paths()` test failure on real Kaggle** — a test assumed non-Kaggle execution; fixed with a `force_env` override parameter so tests are environment-independent. (Caught via real Kaggle test run, not local testing.)
2. **GHSA `references` field schema mismatch** — code assumed a list of `{"url": ...}` dicts (matching OSV's format); GHSA's real API returns a plain list of URL strings. Caused a live `AttributeError` on first real pilot run. Fixed to handle both shapes, with two regression tests pinned to the exact bug.
3. **Regex verb-conjugation gap** — exact-form patterns (`send `, `download `) missed real conjugated advisory text (`sends`, `downloads`). Caught by manually sanity-checking the labeler against realistic (not just hand-picked) text before trusting it on the full corpus.
4. **`out_path` variable collision** — package collection and incident collection both wrote to a variable named `out_path`, causing a later inspection cell to silently read the wrong file (a `KeyError` surfaced this). Fixed by renaming to `out_path_packages` / `out_path_incidents` throughout.
5. **Stale `sys.modules` caching across dataset-version uploads** — recurring issue across the Kaggle workflow where re-uploading a new dataset version didn't take effect because Python had already cached the old `src` package in memory. Standardized fix: clear `sys.modules` entries for `src.*` at the top of every session, or restart the Kaggle session entirely. **Recurred mid-session during the Section 5.5 correction** — an in-memory `TAXONOMY` patch was silently discarded when a later cell re-imported `src.*` after a cache clear, producing one round of misleading (unpatched) statistics before being caught by re-checking `len(TAXONOMY[...].patterns)`. Underscores that in-memory patches are fragile and the permanent-file-write step (Section 7, item 11) matters, not just the in-session fix. **Resolved for good by moving to a local, file-based workflow (Section 5.8).**
6. **`pytest-asyncio` not installed by default** — async tests (`test_registry_clients.py`) failed with "async def functions are not natively supported" until the plugin was explicitly installed; a `pytest.ini` with `asyncio_mode = auto` was added so no per-test marking is needed once the plugin is present.
7. **The construct-validity issue itself (Section 4.1)** — arguably the most important "bug" of the first round: an unverified assumption about what a data source contains, caught only by manually inspecting matched text rather than trusting an aggregate flagged-rate number.
8. **npm taxonomy vocabulary gap (Section 5.5, Bug #1)** — the malware-sophistication taxonomy's regex patterns, despite being correctly derived from real corpus examples (per Section 4.2's fix), were derived almost entirely from PyPI-style examples, producing a flat 0/198 npm malware-flag rate across four independent pipeline executions before diagnosis. A second, narrower instance of the same construct-validity failure mode occurred within the fix itself: a pattern added to catch GHSA's generic "fully compromised" boilerplate was tested, found to merge/flag unrelated incidents on shared non-technical template text, and reverted — caught the same way as the original Section 4.1 bug, by manually inspecting matched text rather than trusting the aggregate flag-rate jump.
9. **npm campaign-level non-independence (Section 5.5, Bug #2)** — near-duplicate advisory records (same package reported by GHSA and OSV under different advisory IDs; same campaign spanning multiple squatted package names) were treated as independent observations, inflating the npm odds ratio to an implausible 178 (p=5×10⁻⁷) on single-digit table cells. Caught by noticing the result's implausibility (an OR that large should prompt suspicion, not excitement) and confirmed via Haldane-Anscombe correction plus manual campaign inspection — not caught by any automated check, underscoring the value of manually sanity-checking extreme statistical results before reporting them.
10. **Ecosystem label mismatch in the check script (Section 5.8, minor)** — the snapshot labels the Python ecosystem `pypi` (lowercase, as GHSA returns it), while the log and an early draft of `run_check.py` used `PyPI`/`pip`. Only affected the printed "expected" comparison column, not any computed statistic; fixed by accepting all three spellings. Noted because it's the kind of cosmetic mismatch that could mask a real discrepancy if left unexplained.

---

## 9. Code Inventory (final state)

```
src/
├── utils/
│   ├── environment.py       Phase 0
│   ├── manifest.py          Phase 0
│   └── checkpointing.py     Phase 0
├── data/
│   ├── leakage_checks.py    Phase 0
│   ├── registry_clients.py  Phase 1 (ported + extended from original notebook)
│   ├── naming_grammar.py    Phase 1 (ported + extended from original notebook Cell 18/12)
│   ├── seed_lists.py        Phase 1 (ported from original notebook Cells 9/10); + fetch_top_npm_names (5.11)
│   ├── collect_packages.py  Phase 1 (new orchestration)
│   ├── incident_clients.py  Phase 1b (new); + extract_reporters (5.10)
│   └── collect_incidents.py Phase 1b (new)
├── labeling/
│   ├── injection_taxonomy.py   Phase 2 (superseded for this corpus; reserved for future skill work)
│   ├── injection_labeler.py    Phase 2 (superseded for this corpus; reserved for future skill work)
│   ├── malware_taxonomy.py     Phase 2b (corrected construct; patched Phase 5.5 for npm coverage — see Section 5.5, bug #8)
│   └── malware_labeler.py      Phase 2b (corrected construct — used in final analysis)
├── evaluation/
│   └── grammar_validation.py  IV validation: hallucinated / benign top-5000 / malware campaigns (5.11)
└── statistics/
    ├── power_analysis.py     Phase 0
    ├── phase0_gate.py        Phase 0
    └── h1_pilot_analysis.py  Phase 2c/2d (contingency table, Fisher's exact, CMH); extended Phase 5.5 with collapse_to_campaign_level() and build_campaign_signature() — see Section 5.5, bug #9

run_check.py  — one-shot reproduction of 5.6 + campaign-level power analysis (Section 5.8); writes results/power_campaign_level.json

tests/  — 11 files (+ tests/fixtures/hallucinated_tiny.txt). 125 passing after Section 5.10; 141 passing after 5.10(d) sensitivity + 5.11 (last verified run)
reports/
├── phase0_go_no_go.md
└── annotation_guidelines.md  (written for injection taxonomy; needs adaptation to malware taxonomy)
data/
├── frozen/
│   └── incidents_snapshot.jsonl  (401 records, frozen Section 5.5, manifest in data/metadata/)
├── external/
│   ├── hallucinated_names.txt (+ _SOURCES.md)   Churilov 2026 "universal" hallucinations, 121 PyPI + 18 npm
│   └── benign_top5000_{pypi,npm}.txt, benign_npm_search_api.txt   cached by grammar_validation (5.11)
└── metadata/  *.manifest.json for the three cached benign lists
results/
├── power_campaign_level.json   (Section 5.8 output; + reporters_d2 key, 5.10)
└── grammar_validation.json     (Section 5.11 output)
```

---

## 10. Honest One-Paragraph Summary

Starting from a prior notebook's package-hallucination-existence classifier, this project built a live-data collection pipeline (control packages + confirmed-malicious incidents from GHSA/OSV, ~400 records), discovered and corrected a construct-validity error in its first labeling approach (the data contains forensic malware narration, not agent-directed injection text), built a corrected malware-sophistication taxonomy grounded in verified real examples — which itself turned out to carry a second, narrower construct-validity gap (near-zero sensitivity to npm/JS-specific phrasing, caught only after four independent pipeline runs produced inconsistent, sign-flipping results) — and separately discovered that campaign-level and cross-source advisory duplication was inflating apparent effect sizes by treating non-independent observations as independent. After fixing both issues, adding regression tests for each, and freezing a snapshot to stop further live-API drift from confounding comparisons, the corrected campaign-level analysis (n=142 independent campaigns) shows **no statistically significant association, in either direction, between predictable package naming and malware payload sophistication, pooled or ecosystem-adjusted.** This supersedes the project's earlier (first-round) reading of a reproducible directional signal, which did not survive the correction. An independent local reproduction then confirmed every reported number and ran the power analysis at the corrected campaign-level n (Section 5.8): ~43% power for OR=2.0, so the null is **underpowered** and rules out only very large effects (OR ≳ 3). The core open work is now, in order: grow the corpus to ~350 independent campaigns (~1,000 raw records), then the fully-controlled regression analysis, and human validation of the labeler given it changed materially.
