"""
Automated leakage detection.

Purpose
-------
Per the project's explicit requirement: severe leakage should cause the
pipeline to FAIL LOUDLY, not silently produce optimistic metrics. Every
function here returns a LeakageReport; the calling training/eval script is
responsible for raising if `severity == "severe"` and the caller hasn't
explicitly acknowledged it.

Checks implemented (matches the Phase 0 spec's five categories):
    1. Duplicate leakage       — same artifact ID in train and test
    2. Name-family leakage     — closely related names split across sets
    3. Temporal leakage        — future metadata used for an earlier-dated prediction
    4. Label leakage           — injection labels correlated with naming-model inputs
    5. Documentation leakage   — post-incident README text in pre-incident eval

This module intentionally has NO ML dependencies (no torch/transformers) so
it can be unit-tested fast and imported anywhere without pulling in heavy
libraries.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class LeakageReport:
    check_name: str
    severity: str  # "none" | "warning" | "severe"
    n_violations: int
    details: list[str] = field(default_factory=list)

    def __bool__(self) -> bool:
        """Report is truthy if there IS a problem, so `if report:` reads
        naturally as 'if leakage detected'."""
        return self.severity != "none"


def check_duplicate_leakage(
    train_ids: list[str], test_ids: list[str]
) -> LeakageReport:
    overlap = set(train_ids) & set(test_ids)
    if not overlap:
        return LeakageReport("duplicate_leakage", "none", 0)
    return LeakageReport(
        check_name="duplicate_leakage",
        severity="severe",
        n_violations=len(overlap),
        details=sorted(overlap)[:20],  # cap for readability
    )


def _name_family_key(name: str, min_stem_len: int = 4) -> str:
    """
    Crude family key: strip common trend-suffixes/prefixes and lowercase,
    so 'react-turbo', 'react-pro', 'react-plus' all collapse to the same
    family key ('react'). This is intentionally simple (not the full
    naming-grammar model from Phase 3) — its only job here is to prevent
    near-identical names from splitting across train/test, which is a
    distinct problem from the grammar classification itself.
    """
    known_affixes = [
        "turbo", "pro", "plus", "ai", "ml", "helper", "utils", "util",
        "core", "lib", "sdk", "cli", "tool", "tools", "kit", "js", "py",
    ]
    stem = name.lower()
    for affix in known_affixes:
        for sep in ("-", "_", "."):
            stem = stem.replace(f"{sep}{affix}", "").replace(f"{affix}{sep}", "")
    stem = stem.strip("-_.")
    if len(stem) < min_stem_len:
        # Too short to be a reliable family key; fall back to full name so
        # we don't accidentally merge unrelated short names into one family.
        return name.lower()
    return stem


def check_name_family_leakage(
    train_names: list[str], test_names: list[str]
) -> LeakageReport:
    train_families = {_name_family_key(n) for n in train_names}
    test_families = {_name_family_key(n) for n in test_names}
    overlap = train_families & test_families
    if not overlap:
        return LeakageReport("name_family_leakage", "none", 0)
    return LeakageReport(
        check_name="name_family_leakage",
        severity="warning",  # warning, not severe: some overlap in generic
        # stems (e.g. 'utils') is expected and not necessarily leakage —
        # a human should review the flagged families, hence "warning" not
        # an automatic hard-fail.
        n_violations=len(overlap),
        details=sorted(overlap)[:20],
    )


def check_temporal_leakage(
    records: list[dict],
    prediction_time_field: str,
    feature_timestamp_fields: list[str],
) -> LeakageReport:
    """
    For each record, verify that every feature-source timestamp is <= the
    prediction time. A feature timestamped AFTER prediction time (e.g., a
    download count or README-modification date collected post-incident)
    invalidates any "early detection" claim built on that record.

    Parameters
    ----------
    records: list of dicts, each must contain `prediction_time_field` and
        all fields listed in `feature_timestamp_fields`.
    prediction_time_field: key holding the ISO timestamp representing "what
        time are we pretending to make this prediction at".
    feature_timestamp_fields: keys holding ISO timestamps for when each
        feature's underlying data was actually observed/collected.
    """
    violations = []
    for i, r in enumerate(records):
        pred_time_raw = r.get(prediction_time_field)
        if pred_time_raw is None:
            violations.append(f"record[{i}]: missing {prediction_time_field}")
            continue
        pred_time = _parse_ts(pred_time_raw)
        for field_name in feature_timestamp_fields:
            feat_time_raw = r.get(field_name)
            if feat_time_raw is None:
                continue  # missing feature timestamp is a data-quality
                # issue, not by itself a leakage issue; handled elsewhere
            feat_time = _parse_ts(feat_time_raw)
            if feat_time is not None and pred_time is not None and feat_time > pred_time:
                violations.append(
                    f"record[{i}]: {field_name}={feat_time_raw} is after "
                    f"{prediction_time_field}={pred_time_raw}"
                )

    if not violations:
        return LeakageReport("temporal_leakage", "none", 0)
    return LeakageReport(
        check_name="temporal_leakage",
        severity="severe",
        n_violations=len(violations),
        details=violations[:20],
    )


def _parse_ts(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def check_label_leakage_correlation(
    naming_features: dict[str, list[float]],
    injection_labels: list[int],
    correlation_threshold: float = 0.9,
) -> LeakageReport:
    """
    The naming-grammar model must be trained WITHOUT injection-label
    information. This check is a coarse guard: if any individual naming
    feature is suspiciously highly correlated with the injection label
    (above `correlation_threshold`), that's a signal the "naming" feature
    set may have accidentally absorbed injection-derived information
    (e.g., a feature that's secretly a proxy for "was flagged by a
    security scanner", which itself correlates with injection presence).

    This is a heuristic, not a proof of leakage — flagged features need
    human review, not automatic removal.
    """
    import math

    violations = []
    n = len(injection_labels)
    if n < 3:
        return LeakageReport(
            "label_leakage_correlation", "warning", 0,
            ["Sample too small (<3) to compute correlation meaningfully."],
        )

    y_mean = sum(injection_labels) / n
    y_var = sum((y - y_mean) ** 2 for y in injection_labels)

    for feat_name, values in naming_features.items():
        if len(values) != n:
            violations.append(
                f"{feat_name}: length mismatch ({len(values)} vs {n} labels)"
            )
            continue
        x_mean = sum(values) / n
        x_var = sum((x - x_mean) ** 2 for x in values)
        cov = sum(
            (values[i] - x_mean) * (injection_labels[i] - y_mean) for i in range(n)
        )
        if x_var == 0 or y_var == 0:
            continue
        r = cov / math.sqrt(x_var * y_var)
        if abs(r) >= correlation_threshold:
            violations.append(f"{feat_name}: |r|={abs(r):.3f} with injection_label")

    if not violations:
        return LeakageReport("label_leakage_correlation", "none", 0)
    return LeakageReport(
        check_name="label_leakage_correlation",
        severity="warning",
        n_violations=len(violations),
        details=violations,
    )


def check_documentation_version_leakage(
    records: list[dict],
    doc_snapshot_time_field: str,
    incident_report_time_field: str,
) -> LeakageReport:
    """
    Flags records where the documentation snapshot used for feature
    extraction was collected AFTER the incident report date — i.e., the
    README/docstring text you're using may already reflect a post-incident
    edit (payload removed by maintainer, or added by attacker after initial
    benign release), which would corrupt any "would we have caught this
    before disclosure" claim (Phase 14).
    """
    violations = []
    for i, r in enumerate(records):
        doc_time = _parse_ts(r.get(doc_snapshot_time_field, ""))
        report_time = _parse_ts(r.get(incident_report_time_field, ""))
        if doc_time is None or report_time is None:
            continue
        if doc_time > report_time:
            violations.append(
                f"record[{i}]: doc snapshot ({doc_time.isoformat()}) is "
                f"after incident report ({report_time.isoformat()})"
            )

    if not violations:
        return LeakageReport("documentation_version_leakage", "none", 0)
    return LeakageReport(
        check_name="documentation_version_leakage",
        severity="severe",
        n_violations=len(violations),
        details=violations[:20],
    )


def run_all_checks(**kwargs) -> list[LeakageReport]:
    """
    Convenience runner. Each check is optional — pass only the kwargs
    relevant to the data you have; missing inputs simply skip that check
    rather than erroring, since not every pipeline stage has all the
    necessary fields available yet.
    """
    reports: list[LeakageReport] = []

    if "train_ids" in kwargs and "test_ids" in kwargs:
        reports.append(
            check_duplicate_leakage(kwargs["train_ids"], kwargs["test_ids"])
        )
    if "train_names" in kwargs and "test_names" in kwargs:
        reports.append(
            check_name_family_leakage(kwargs["train_names"], kwargs["test_names"])
        )
    if "temporal_records" in kwargs:
        reports.append(
            check_temporal_leakage(
                kwargs["temporal_records"],
                kwargs["prediction_time_field"],
                kwargs["feature_timestamp_fields"],
            )
        )
    if "naming_features" in kwargs and "injection_labels" in kwargs:
        reports.append(
            check_label_leakage_correlation(
                kwargs["naming_features"], kwargs["injection_labels"]
            )
        )
    if "doc_version_records" in kwargs:
        reports.append(
            check_documentation_version_leakage(
                kwargs["doc_version_records"],
                kwargs["doc_snapshot_time_field"],
                kwargs["incident_report_time_field"],
            )
        )

    return reports


def assert_no_severe_leakage(reports: list[LeakageReport]) -> None:
    """Call this at the end of any pipeline stage. Raises loudly on
    'severe' — this is the 'fail loudly' behavior the spec requires."""
    severe = [r for r in reports if r.severity == "severe"]
    if severe:
        msg_lines = ["SEVERE LEAKAGE DETECTED — pipeline halted.\n"]
        for r in severe:
            msg_lines.append(f"  [{r.check_name}] {r.n_violations} violation(s)")
            for d in r.details[:5]:
                msg_lines.append(f"    - {d}")
        raise RuntimeError("\n".join(msg_lines))
