"""
Phase 0 go/no-go gate report generator.

Consumes pilot counts (from whatever small initial collection pass you've
done — Phase 1 in the overall plan) and produces
`reports/phase0_go_no_go.md` with an explicit GO / GO-WITH-REDUCED-SCOPE /
NO-GO decision, using the thresholds in config/base.yaml and the power
analysis in power_analysis.py.

This does not collect data itself. It's the decision layer that sits on
top of whatever collection code Phase 1 produces.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from src.statistics.power_analysis import summarize_power


@dataclass
class Phase0PilotCounts:
    n_confirmed_incidents_total: int
    n_confirmed_incidents_with_injection_label: int
    n_injection_present: int
    n_control_sample: int
    n_control_injection_present: int
    n_skills_total: int
    n_skills_malicious: int
    n_skills_with_injection: int
    n_events_with_usable_date: int
    label_missingness_pct: float
    timestamp_missingness_pct: float


def decide_gate(counts: Phase0PilotCounts, thresholds: dict) -> tuple[str, list[str]]:
    """
    Returns (decision, reasons). Decision is one of:
        "GO", "GO_WITH_REDUCED_SCOPE", "NO_GO"

    Logic is deliberately conservative and simple — this is a gate meant to
    stop wasted effort, not a sophisticated model. If in doubt, it should
    push toward REDUCED_SCOPE rather than NO_GO, since a reduced-scope
    primary claim (H1 only) is still a legitimate contribution per the
    Phase 0 audit's "minimum viable Q1 experiment" recommendation.
    """
    reasons = []
    hard_fail = False
    reduce_scope = False

    if counts.n_confirmed_incidents_with_injection_label < thresholds[
        "min_confirmed_incidents_with_injection_label"
    ]:
        reduce_scope = True
        reasons.append(
            f"Confirmed incidents with a usable injection label "
            f"({counts.n_confirmed_incidents_with_injection_label}) below "
            f"target ({thresholds['min_confirmed_incidents_with_injection_label']})."
        )

    if counts.n_control_sample < thresholds["min_control_sample_size"]:
        reduce_scope = True
        reasons.append(
            f"Control sample ({counts.n_control_sample}) below target "
            f"({thresholds['min_control_sample_size']})."
        )

    if counts.n_events_with_usable_date < thresholds["min_events_with_usable_date"]:
        reasons.append(
            f"Events with usable date for H1b ({counts.n_events_with_usable_date}) "
            f"below target ({thresholds['min_events_with_usable_date']}) — "
            f"H1b will be exploratory only, not a hard blocker for H1."
        )

    if counts.n_confirmed_incidents_with_injection_label == 0:
        hard_fail = True
        reasons.append(
            "ZERO confirmed incidents with an injection label. H1 is not "
            "testable with this data source alone. This is a NO-GO for H1 "
            "as specified — either broaden incident sources or reframe the "
            "study around a different primary hypothesis."
        )

    if counts.label_missingness_pct > 50 or counts.timestamp_missingness_pct > 50:
        reduce_scope = True
        reasons.append(
            f"High missingness (label={counts.label_missingness_pct:.1f}%, "
            f"timestamp={counts.timestamp_missingness_pct:.1f}%) — data "
            f"quality risk even if raw counts look adequate."
        )

    if hard_fail:
        return "NO_GO", reasons
    if reduce_scope:
        return "GO_WITH_REDUCED_SCOPE", reasons
    return "GO", reasons or ["All pilot thresholds met."]


def generate_report(
    counts: Phase0PilotCounts,
    thresholds: dict,
    output_path: Path,
) -> Path:
    decision, reasons = decide_gate(counts, thresholds)

    flagged_rate = (
        counts.n_injection_present / counts.n_confirmed_incidents_with_injection_label
        if counts.n_confirmed_incidents_with_injection_label > 0
        else 0.0
    )
    control_rate = (
        counts.n_control_injection_present / counts.n_control_sample
        if counts.n_control_sample > 0
        else 0.0
    )

    power_block = summarize_power(
        pilot_n_flagged=counts.n_confirmed_incidents_with_injection_label,
        pilot_n_control=counts.n_control_sample,
        pilot_injection_rate_flagged=flagged_rate,
        pilot_injection_rate_control=control_rate,
        pilot_n_events_with_known_date=counts.n_events_with_usable_date,
    )

    lines = []
    lines.append("# Phase 0 Go/No-Go Report")
    lines.append(f"\nGenerated: {datetime.now(timezone.utc).isoformat()}\n")
    lines.append(f"## DECISION: **{decision}**\n")
    lines.append("### Reasons\n")
    for r in reasons:
        lines.append(f"- {r}")
    lines.append("")

    lines.append("## Pilot Counts\n")
    lines.append(f"- Confirmed incidents (total): {counts.n_confirmed_incidents_total}")
    lines.append(
        f"- Confirmed incidents with usable injection label: "
        f"{counts.n_confirmed_incidents_with_injection_label}"
    )
    lines.append(f"- Injection present among those: {counts.n_injection_present}")
    lines.append(f"- Control sample size: {counts.n_control_sample}")
    lines.append(
        f"- Injection present in control: {counts.n_control_injection_present}"
    )
    lines.append(f"- Skills total: {counts.n_skills_total}")
    lines.append(f"- Skills malicious: {counts.n_skills_malicious}")
    lines.append(f"- Skills with injection: {counts.n_skills_with_injection}")
    lines.append(f"- Events with usable date (H1b): {counts.n_events_with_usable_date}")
    lines.append(f"- Label missingness: {counts.label_missingness_pct:.1f}%")
    lines.append(f"- Timestamp missingness: {counts.timestamp_missingness_pct:.1f}%")
    lines.append("")

    lines.append(power_block)
    lines.append("")

    lines.append("## Next Action\n")
    if decision == "NO_GO":
        lines.append(
            "Do not proceed to Phase 1 full collection or any modeling. "
            "Revisit incident-source strategy (see Phase 0 audit: consider "
            "broader/non-grammar-curated sources such as Backstabber's "
            "Knife Collection or MalwareBench to raise the injection-"
            "labeled incident count) before re-running this gate."
        )
    elif decision == "GO_WITH_REDUCED_SCOPE":
        lines.append(
            "Proceed, but treat H1 (association) as the sole PRIMARY claim. "
            "Downgrade H1b to exploratory (descriptive Kaplan-Meier only, "
            "no significance claimed) unless later collection substantially "
            "improves event counts. Re-run this gate after full Phase 1 "
            "collection completes, before committing to final analyses."
        )
    else:
        lines.append(
            "Proceed with full Phase 1 plan. Re-run this gate after full "
            "collection completes to confirm pilot estimates held."
        )

    report_text = "\n".join(lines)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(report_text)
    return output_path


if __name__ == "__main__":
    # Example / smoke-test invocation with placeholder pilot numbers.
    # Replace with real counts once Phase 1 pilot collection exists.
    example_counts = Phase0PilotCounts(
        n_confirmed_incidents_total=40,
        n_confirmed_incidents_with_injection_label=12,
        n_injection_present=5,
        n_control_sample=60,
        n_control_injection_present=1,
        n_skills_total=0,
        n_skills_malicious=0,
        n_skills_with_injection=0,
        n_events_with_usable_date=6,
        label_missingness_pct=15.0,
        timestamp_missingness_pct=25.0,
    )
    thresholds = {
        "min_confirmed_incidents_with_injection_label": 30,
        "min_control_sample_size": 100,
        "min_events_with_usable_date": 15,
    }
    out = generate_report(
        example_counts, thresholds, Path("reports/phase0_go_no_go.md")
    )
    print(f"Report written to {out}")
