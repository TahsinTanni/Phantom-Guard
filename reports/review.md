# Phantom Guard — Internal Review (reviewer-style)

**Date:** 2026-10-03
**Basis (revised after an independent reproduction found two errors in A2 — see that section):** full read of `src/` (naming_grammar, malware_taxonomy, malware_labeler, h1_pilot_analysis, power_analysis, incident_clients, collect_incidents), the research log through Section 5.8, and diagnostics run against the frozen 401-record snapshot. Every number below was computed on that snapshot and is reproducible with the code in `review_diagnostics.py`.

**Verdict in one line:** the engineering hygiene is well above average (frozen snapshot, regression tests, independence guarantee, honest null), but **both measurement instruments have unvalidated construct validity, and the headline null is unstable to an unexamined text-source choice.** The paper is not publishable as framed; it is salvageable with the work in Section D.

---

## A. Critical — these threaten the central claim

### A1. The independent variable does not measure "hallucination-prone naming"

`naming_grammar.py` flags a name if any token is in a list of ~38 common package-name words (`py`, `tools`, `ai`, `client`, `api`, `react`, `aws`, …). Those lists were designed in the prior notebook to *generate plausible-looking names* — i.e. to look like real packages. Run in reverse, they detect *ordinary compound naming*, not LLM hallucination.

Evidence:
- Of 37 well-known legitimate packages tried, **16 (43%) are flagged**: `pandas`, `flask`, `django`, `react`, `vue`, `express`, `react-dom`, `@types/node`, `@aws-sdk/client-s3`, `azure-core`, `langchain-core`, `ai`, …
- In the corpus, the flag is driven by `py` (8 campaigns), `tools` (5), `ai` (4), `client` (4). `py-` is simply how PyPI packages are named.
- The one list that is conceptually about LLM style — `TREND_SUFFIXES` (`turbo`, `pro`, `plus`, …) — fires on **4 of 142 campaigns**. The hallucination-flavoured part of the IV has essentially no data.
- Nowhere in the project is the grammar validated against actual LLM-hallucinated package names. The claim that it captures "the kind of pattern an LLM is prone to hallucinate" is asserted, never tested.

**Consequence:** H1 as currently run tests "do generically-named malware packages get more detailed write-ups than others?" — not the research question in the title.

**Fix:** (a) obtain a set of real hallucinated package names (Spracklen et al. released theirs; several slopsquatting datasets exist) and a benign set (seed_lists already fetches top-N PyPI/npm); report the grammar's sensitivity/specificity. If it does not separate them, the IV must be replaced (e.g. a model-based hallucination-likelihood score, or direct "was this name ever hallucinated by an LLM" lookup). (b) Regardless, report the IV's base rate on benign packages in the paper — it is currently unknown and probably ~30–40%.

### A2. The headline null flips sign depending on which advisory text is read

Every package in the snapshot has **both** a GHSA record and an OSV record (200 unique packages; 401 records because one package has two OSV entries). The two texts differ (identical opening in only 74/200), and the regex labeler disagrees between them on **20/200 packages — all in one direction** (OSV positive, GHSA negative). `collapse_to_campaign_level()` uses "any member positive", so whichever text matches wins.

**Corrected 2026-10-03 after independent check:** the first version of this table let the campaign grouping change with the text source (the campaign signature is built from the description). The table below holds the grouping fixed at the 142 any-source campaigns and varies *only* the DV text, which is the clean comparison.

| DV text used | Pooled table | OR | p |
|---|---|---|---|
| Any source (Section 5.6 setting) | [[20,17],[60,45]] | **0.88** | 0.85 |
| OSV text only | [[20,17],[60,45]] | 0.88 | 0.85 |
| GHSA text only | [[20,17],[40,65]] | **1.91** | 0.12 |
| GHSA only, npm stratum | [[7,7],[6,22]] | 3.67 | 0.08 |
| GHSA only, PyPI stratum | [[13,10],[34,43]] | 1.64 | 0.35 |

(The Section 5.6 figure of [[20,17],[61,44]] / OR 0.849 differs by one campaign because the pipeline aggregates "any" across *records* before name-level collapse; the one package with two OSV records accounts for it. Immaterial to the conclusion; noted for exactness.)

The point estimate crosses 1 depending on a choice the log does not mention. The 20 disagreements are also unevenly distributed: **0/20 are grammar-flagged vs 37/200 overall (Fisher p = 0.029)**; 15 of the 20 are PyPI. That needs a hand inspection — it may be a labeler artifact (OSV `MAL-` entries aggregate multiple reporters, median length 1523 vs 948 chars → more regex surface), in which case the GHSA-only row is the more trustworthy one.

**Fix:** pick one canonical text per package (GHSA is the primary source; OSV mostly mirrors it) and justify it; report the other as a sensitivity analysis; hand-inspect the 20 disagreements and say what they are. When implementing, vary text source and campaign grouping as *separate* switches, and index records per source as lists (a package can have more than one record from the same source). Do not use "any member positive" across *sources* — it is defensible across *names in a campaign*, which is a different thing.

### A3. The dependent variable is a property of the reporter, not the malware

The DV is "advisory text matches a mechanism regex." Whether a mechanism is described depends on who wrote the advisory. The snapshot's reporters (parsed from `## Source:` headers) differ sharply on both axes:

| Reporter (campaign level) | n | grammar-flag rate | DV rate |
|---|---|---|---|
| kam193 | 82 | 0.22 | 0.60 |
| amazon-inspector | 29 | 0.41 | 0.41 |
| other | 17 | 0.41 | 0.88 |
| GHSA generic boilerplate | 13 | **0.00** | 0.38 |

GHSA's no-detail boilerplate ("…should be considered fully compromised…") appears in **0/74 flagged records vs 26/327 non-flagged**. Reporter is correlated with the IV and with the DV → it is a confounder, and it is not controlled anywhere. (The README's Section 8 names "detection bias" as a risk; it was never modelled.)

**Fix:** extract reporter into a field at collection time; stratify (CMH over reporter × ecosystem) and include it in the planned regression. Report the boilerplate rate by flag status explicitly.

---

## B. Major — must be addressed before submission

### B1. The corpus is one month of advisories, 200 packages, with one family supplying 30% of them
- 386 of 401 records were published **Sept–Oct 2026**. GHSA's API returns newest first; 5 pages = the latest ~5 weeks. This is a temporal convenience sample, not "the incident corpus."
- 401 records = **200 unique packages** (every package appears once from GHSA and once from OSV). The log's "~400 records" overstates n by 2×.
- The two largest campaign groups (45 + 15 names) are both the Baileys/WhatsApp "PhantomSub" fork family — likely one campaign, not two (the collapse split them on wording). So **npm = one giant family + ~40 singletons**; npm's stratum effectively has no independent data, and any npm result is a statement about one actor.
- Group-size distribution: 140 singletons, 1×15, 1×45.

**Fix:** state the sampling window and n honestly; grow the corpus *backward in time* (more GHSA pages — that is what more pages gives), and report per-year/per-month counts; merge the two Baileys groups or justify not doing so; report n as campaigns everywhere, never records.

### B2. No benign comparison group
All 142 units are confirmed-malicious. The paper's framing (predictable naming → risk) requires knowing the IV's rate among *benign* packages. The 20-package control sample is far too small and unused (log Section 7 item 2). Given A1's 43% hit rate on famous packages, a within-malware comparison cannot be interpreted as anything about hallucination risk.

**Fix:** at minimum, compute the flag rate over top-5,000 PyPI and npm names (the seed-list code exists) as a descriptive base rate. Better: a matched design (malicious vs benign, matched on ecosystem and token count).

### B3. "Sophistication" is not measured; "any regex hit" is
The title promises payload *sophistication*. The DV is binary presence of any of six mechanism patterns. An ordinal version (number of distinct categories) shows nothing: flagged mean 0.78 vs non-flagged 0.73, Mann-Whitney p=0.93. Either (a) drop the word "sophistication" and call the DV "described mechanism present," or (b) build a real sophistication score (e.g. distinct TTP count validated by annotators, or an analyst rating).

### B4. No human validation of the labeler (known, item 5 — but it is now blocking)
Record-level flag rates after the npm patch are **npm 59.5%, PyPI 54.7%**, roughly double the pre-patch ~29%. PyPI moved too, so the npm-aware patterns are firing on PyPI text. Several patterns are loose (`backdoor`, `impersonat\w*`, `(POST|post)\w*\s+.{0,80}(hardcoded|collector|endpoint|webhook)`). Until precision/recall per category is measured on a hand-labelled sample, every DV number is provisional.

**Fix:** 100-record stratified sample (by ecosystem × reporter), two annotators, Cohen's κ, per-category precision/recall. Prioritise the 20 GHSA/OSV disagreements from A2 and 20 random npm positives.

---

## C. Minor / already fine

- **Circularity via `brand_impersonation_narrative`** (prose about the name feeding the DV): empirically negligible — excluding it moves OR from 0.85 to 0.88. Report as a sensitivity row and move on.
- **Campaign collapse** is sound in concept and the boilerplate-exclusion rule is correct. Add a check that the signature does not merge *different* campaigns from the *same* reporter template (none found in this snapshot, but it will matter as the corpus grows).
- **Power analysis (5.8)** is correct for the design it assumes; note it assumes the IV is valid and the DV is measured without error — both currently false, which only makes the true power lower.
- **Confidence intervals** are still missing (item 6). Trivial to add (`statsmodels.stats.contingency_tables.Table2x2`).
- **Tests, snapshot, manifests, independence guarantee**: good; keep.
- **Title:** "Naming-Grammar Signals and Malicious-Payload Sophistication …" overclaims both constructs. An honest working title: *Do compound package names predict described payload mechanisms in GHSA malware advisories? A null pilot and its limits.*

---

## D. Recommended order of work

| # | Task | Effort | Decides |
|---|---|---|---|
| 1 | Canonical text source (GHSA), rerun 5.6, hand-inspect the 20 disagreements | ½ day | whether the null is even the right headline |
| 2 | Parse reporter; add reporter × ecosystem CMH; report boilerplate by flag | ½ day | whether A3 explains the result |
| 3 | IV validation: grammar vs real hallucinated names and vs top-5k benign names; report sens/spec and benign base rate | 2–3 days | **whether the paper survives as framed** |
| 4 | Human annotation of 100 records; κ, precision/recall per category | 2–3 days (two people) | whether the DV is trustworthy |
| 5 | Grow corpus backward in time to ~1,000 raw / ~350 campaigns; re-freeze; merge Baileys groups | 1 day + API time | power |
| 6 | Logistic regression: DV ~ grammar + ecosystem + reporter + year (+ doc_length) with CIs | ½ day | the actual H1 test |
| 7 | Rewrite title, abstract, limitations around what was measured | — | — |

Step 3 is the fork in the road. If the grammar does not separate hallucinated from real names, the right paper is a different one: the corpus, the campaign-collapse method, and the reporter-bias finding are publishable as a measurement/methods contribution, and the hallucination angle needs a validated instrument before it can be tested.

---

## E. What is good and should be kept

The construct-validity corrections (4.1 → 4.2, then 5.5) are exactly how this should be done and are a strength to write up. The campaign-collapse step is a real methodological contribution — most package-malware papers treat advisory records as independent and they are not. The frozen, checksummed snapshot plus independent reproduction (5.8) is better practice than most published work in this area. The weakness is not rigour; it is that rigour was applied downstream of two instruments that were never validated upstream.
