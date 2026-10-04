# Phase 0 Go/No-Go Report

Generated: 2026-08-19T18:31:28.202914+00:00

## DECISION: **GO_WITH_REDUCED_SCOPE**

### Reasons

- Confirmed incidents with a usable injection label (12) below target (30).
- Control sample (60) below target (100).
- Events with usable date for H1b (6) below target (15) — H1b will be exploratory only, not a hard blocker for H1.

## Pilot Counts

- Confirmed incidents (total): 40
- Confirmed incidents with usable injection label: 12
- Injection present among those: 5
- Control sample size: 60
- Injection present in control: 1
- Skills total: 0
- Skills malicious: 0
- Skills with injection: 0
- Events with usable date (H1b): 6
- Label missingness: 15.0%
- Timestamp missingness: 25.0%

## Power analysis (pilot-based estimate)

- Pilot flagged (grammar-match) n: 12
- Pilot control n: 60
- Pilot injection rate, flagged: 0.417
- Pilot injection rate, control: 0.017
- Pilot events with a usable date for survival analysis: 6

- Approx. total n required to detect OR=2.0 at 80% power: 3988
- Approx. events required: 67
- Note: Approximation for a single binary exposure with no additional covariates. Adding controls (ecosystem, age, popularity, doc length) will increase the required n further — treat this as a lower bound, not a target.

- Approx. events required for H1b (Cox PH, HR=2.0, 80% power): 66
  Note: This is the number of OBSERVED EVENTS required (injection appearances with a known/bounded date), not total sample size. Given expected heavy censoring and timestamp-quality problems flagged in the Phase 0 audit, expect the true achievable event count to be well below what a naive total-n figure would suggest. If achieved events < this figure, H1b must be downgraded to exploratory/descriptive (Kaplan-Meier only, no hypothesis test claimed).

**RECOMMENDATION:** H1b is likely underpowered at current pilot scale. Proceed with H1 as PRIMARY; treat H1b as EXPLORATORY (report Kaplan-Meier curves and effect direction without claiming statistical significance) unless the full collection substantially exceeds pilot-implied event counts.

## Next Action

Proceed, but treat H1 (association) as the sole PRIMARY claim. Downgrade H1b to exploratory (descriptive Kaplan-Meier only, no significance claimed) unless later collection substantially improves event counts. Re-run this gate after full Phase 1 collection completes, before committing to final analyses.