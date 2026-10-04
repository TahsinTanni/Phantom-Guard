"""
Power analysis for H1 (association) and H1b (time-to-event).

Purpose
-------
Per the Phase 0 audit: do not spend GPU time or annotation effort on an
underpowered hypothesis. This module answers, BEFORE data collection is
finalized, "how many events do we need to detect an effect of a given
size, and does our pilot count suggest we'll have that many?"

Scope and honesty note
-----------------------
These are approximate, standard power-analysis formulas (Demidenko-style
approximation for logistic regression; events-per-variable rule of thumb
plus a log-rank-test power approximation for survival). They are meant to
produce a GO / GO-WITH-REDUCED-SCOPE / NO-GO signal, not a publication-
grade a priori power computation. If the study proceeds, report power
based on the ACTUAL achieved sample post-collection, not this estimate.
"""

from __future__ import annotations

import math
from dataclasses import dataclass


@dataclass
class LogisticPowerResult:
    n_total: int
    n_events_required_approx: int
    achievable: bool
    notes: str


def logistic_regression_power(
    p_control: float,
    odds_ratio_to_detect: float,
    alpha: float = 0.05,
    power: float = 0.80,
    exposure_prevalence: float = 0.5,
) -> LogisticPowerResult:
    """
    Approximate minimum total sample size to detect a given odds ratio in a
    logistic regression with a single binary exposure (grammar_match),
    using the standard Hsieh/Demidenko-style approximation:

        n = (z_alpha/2 + z_beta)^2 / (p_bar * (1-p_bar) * exposure_prevalence
             * (1-exposure_prevalence) * log(OR)^2)

    Parameters
    ----------
    p_control: baseline outcome rate (injection presence) among NON-flagged
        artifacts. This is your single most important pilot number — get it
        from Phase 0 data collection before trusting this function's output.
    odds_ratio_to_detect: smallest effect size you actually care about
        detecting. Do not set this to whatever your pilot data happens to
        show — that's circular. Set it to the smallest OR that would be
        practically meaningful (e.g., OR=2.0 as a conventional default if
        you have no stronger prior).
    exposure_prevalence: fraction of your matched sample that is
        grammar-flagged (often ~0.5 by design if you 1:1 match).
    """
    from scipy.stats import norm

    z_alpha = norm.ppf(1 - alpha / 2)
    z_beta = norm.ppf(power)

    p_bar = p_control  # approximation; refine with exact formula if needed
    log_or = math.log(odds_ratio_to_detect)

    denom = (
        p_bar
        * (1 - p_bar)
        * exposure_prevalence
        * (1 - exposure_prevalence)
        * (log_or**2)
    )
    if denom <= 0:
        return LogisticPowerResult(
            n_total=math.inf,
            n_events_required_approx=math.inf,  # type: ignore[arg-type]
            achievable=False,
            notes="Degenerate input (p_control in {0,1} or OR=1); cannot compute.",
        )

    n_total = math.ceil(((z_alpha + z_beta) ** 2) / denom)

    # Rule-of-thumb minimum events-per-variable check (Peduzzi et al.):
    # at least ~10 events per covariate for stable logistic regression.
    n_events_required = max(10, math.ceil(n_total * p_bar))

    return LogisticPowerResult(
        n_total=n_total,
        n_events_required_approx=n_events_required,
        achievable=True,
        notes=(
            "Approximation for a single binary exposure with no additional "
            "covariates. Adding controls (ecosystem, age, popularity, doc "
            "length) will increase the required n further — treat this as "
            "a lower bound, not a target."
        ),
    )


@dataclass
class SurvivalPowerResult:
    total_events_required_approx: int
    achievable_note: str


def coxph_power_approx(
    hazard_ratio_to_detect: float,
    exposure_prevalence: float = 0.5,
    alpha: float = 0.05,
    power: float = 0.80,
) -> SurvivalPowerResult:
    """
    Approximate required NUMBER OF EVENTS (not total n) for a Cox PH model
    with one binary covariate, using the standard Schoenfeld (1983)
    formula:

        d = (z_alpha/2 + z_beta)^2 / (exposure_prevalence * (1-exposure_prevalence)
             * log(HR)^2)

    This is events, not sample size — for time-to-event data with heavy
    censoring (likely here, since most artifacts in your corpus will never
    be observed to have an injection payload appear), total sample size
    can be many multiples of the required event count.
    """
    from scipy.stats import norm

    z_alpha = norm.ppf(1 - alpha / 2)
    z_beta = norm.ppf(power)
    log_hr = math.log(hazard_ratio_to_detect)

    denom = exposure_prevalence * (1 - exposure_prevalence) * (log_hr**2)
    if denom <= 0:
        return SurvivalPowerResult(
            total_events_required_approx=math.inf,  # type: ignore[arg-type]
            achievable_note="Degenerate input (HR=1); cannot compute.",
        )

    d = math.ceil(((z_alpha + z_beta) ** 2) / denom)

    return SurvivalPowerResult(
        total_events_required_approx=d,
        achievable_note=(
            "This is the number of OBSERVED EVENTS required (injection "
            "appearances with a known/bounded date), not total sample size. "
            "Given expected heavy censoring and timestamp-quality problems "
            "flagged in the Phase 0 audit, expect the true achievable event "
            "count to be well below what a naive total-n figure would "
            "suggest. If achieved events < this figure, H1b must be "
            "downgraded to exploratory/descriptive (Kaplan-Meier only, no "
            "hypothesis test claimed)."
        ),
    )


def summarize_power(
    pilot_n_flagged: int,
    pilot_n_control: int,
    pilot_injection_rate_flagged: float,
    pilot_injection_rate_control: float,
    pilot_n_events_with_known_date: int,
) -> str:
    """
    Produces the plain-text block to paste into reports/phase0_go_no_go.md.
    Takes PILOT numbers (from a small initial collection pass) and reports
    whether they suggest the full collection will reach an adequately
    powered sample — this does not replace re-running power analysis on the
    final achieved sample.
    """
    lines = []
    lines.append("## Power analysis (pilot-based estimate)\n")
    lines.append(f"- Pilot flagged (grammar-match) n: {pilot_n_flagged}")
    lines.append(f"- Pilot control n: {pilot_n_control}")
    lines.append(
        f"- Pilot injection rate, flagged: {pilot_injection_rate_flagged:.3f}"
    )
    lines.append(
        f"- Pilot injection rate, control: {pilot_injection_rate_control:.3f}"
    )
    lines.append(
        f"- Pilot events with a usable date for survival analysis: "
        f"{pilot_n_events_with_known_date}"
    )
    lines.append("")

    if pilot_injection_rate_control <= 0:
        lines.append(
            "**WARNING:** zero observed injection presence in the control "
            "group during the pilot. Cannot estimate a meaningful odds "
            "ratio power target from this alone; either the true control "
            "base rate is near zero (plausible, and would itself be a "
            "reportable finding) or the pilot is too small. Increase pilot "
            "size before deciding GO/NO-GO on H1."
        )
        return "\n".join(lines)

    result = logistic_regression_power(
        p_control=pilot_injection_rate_control,
        odds_ratio_to_detect=2.0,
        exposure_prevalence=0.5,
    )
    lines.append(
        f"- Approx. total n required to detect OR=2.0 at 80% power: "
        f"{result.n_total}"
    )
    lines.append(f"- Approx. events required: {result.n_events_required_approx}")
    lines.append(f"- Note: {result.notes}")
    lines.append("")

    surv = coxph_power_approx(hazard_ratio_to_detect=2.0, exposure_prevalence=0.5)
    lines.append(
        f"- Approx. events required for H1b (Cox PH, HR=2.0, 80% power): "
        f"{surv.total_events_required_approx}"
    )
    lines.append(f"  Note: {surv.achievable_note}")
    lines.append("")

    if pilot_n_events_with_known_date < surv.total_events_required_approx:
        lines.append(
            "**RECOMMENDATION:** H1b is likely underpowered at current "
            "pilot scale. Proceed with H1 as PRIMARY; treat H1b as "
            "EXPLORATORY (report Kaplan-Meier curves and effect direction "
            "without claiming statistical significance) unless the full "
            "collection substantially exceeds pilot-implied event counts."
        )
    else:
        lines.append(
            "**RECOMMENDATION:** Pilot-implied event count for H1b meets "
            "the approximate threshold. Proceed with H1b as a co-primary "
            "analysis, but re-verify power on the actual achieved sample "
            "before finalizing the paper's claims."
        )

    return "\n".join(lines)
