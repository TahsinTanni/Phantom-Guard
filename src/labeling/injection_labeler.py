"""
Heuristic (rule-based) injection-payload labeler.

Purpose
-------
First-pass candidate flagging over free text (summary + description from
incident_clients.py / registry_clients.py's readme_text). NOT final
ground truth — per the Phase 0 audit, this output must still go through
human review and inter-annotator agreement measurement before being
trusted as H1's dependent variable. What this module guarantees is
TRANSPARENCY: every flag comes with the exact matched pattern and text
span, so a human reviewer isn't starting from nothing.

Independence guarantee
------------------------
`label_text()` takes ONLY a string. It has no parameter for package name,
grammar_match, or any naming-derived feature — this is a structural
guarantee against the circularity the Phase 0 audit warns about, not just
a documented convention. If you find yourself wanting to pass a name in
"just to improve accuracy," don't — that breaks H1.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from src.labeling.injection_taxonomy import TAXONOMY, InjectionCategory


@dataclass
class CategoryMatch:
    category: InjectionCategory
    matched_pattern: str
    matched_text: str
    span: tuple[int, int]


@dataclass
class InjectionLabelResult:
    injection_present_candidate: bool
    matches: list[CategoryMatch] = field(default_factory=list)
    matched_categories: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "injection_present_candidate": self.injection_present_candidate,
            "matched_categories": self.matched_categories,
            "matches": [
                {
                    "category": m.category.value,
                    "matched_pattern": m.matched_pattern,
                    "matched_text": m.matched_text,
                    "span": list(m.span),
                }
                for m in self.matches
            ],
        }


def label_text(text: str, context_chars: int = 60) -> InjectionLabelResult:
    """
    Scans `text` against every category's patterns in the taxonomy
    (excluding BENIGN_INSTRUCTION_LIKE, which is never auto-matched by
    design — see injection_taxonomy.py).

    Returns a candidate label, not a final one. `injection_present_candidate`
    is True if ANY pattern matched. This is intentionally permissive
    (favors false positives over false negatives at this stage) since
    human review is the next required step, not a nice-to-have.
    """
    if not text:
        return InjectionLabelResult(injection_present_candidate=False)

    matches: list[CategoryMatch] = []
    text_lower = text  # patterns already use re.IGNORECASE below

    for category, definition in TAXONOMY.items():
        if category == InjectionCategory.BENIGN_INSTRUCTION_LIKE:
            continue
        for pattern in definition.patterns:
            for m in re.finditer(pattern, text_lower, flags=re.IGNORECASE):
                start = max(0, m.start() - context_chars)
                end = min(len(text), m.end() + context_chars)
                matches.append(
                    CategoryMatch(
                        category=category,
                        matched_pattern=pattern,
                        matched_text=text[start:end],
                        span=(m.start(), m.end()),
                    )
                )

    matched_categories = sorted({m.category.value for m in matches})
    return InjectionLabelResult(
        injection_present_candidate=len(matches) > 0,
        matches=matches,
        matched_categories=matched_categories,
    )


def label_incident_record(record: dict) -> dict:
    """
    Convenience wrapper for incident_clients.py-shaped records: combines
    `summary` + `description` (the only two free-text fields available)
    and returns the record with a `heuristic_label` block attached.

    Deliberately does NOT touch `package_name`, `ecosystem`, or any other
    field on the record — only reads the two text fields, preserving the
    independence guarantee at the call-site level too.
    """
    combined_text = f"{record.get('summary', '')}\n{record.get('description', '')}"
    result = label_text(combined_text)
    return {**record, "heuristic_label": result.to_dict()}


def label_batch(records: list[dict]) -> list[dict]:
    return [label_incident_record(r) for r in records]


def summarize_labeling(labeled_records: list[dict]) -> dict:
    """
    Aggregate stats for a labeled batch — this is what feeds the
    Phase 0 gate's n_confirmed_incidents_with_injection_label /
    n_injection_present fields once a human-reviewed sample confirms the
    heuristic's precision.
    """
    total = len(labeled_records)
    flagged = sum(
        1 for r in labeled_records if r["heuristic_label"]["injection_present_candidate"]
    )
    category_counts: dict[str, int] = {}
    for r in labeled_records:
        for cat in r["heuristic_label"]["matched_categories"]:
            category_counts[cat] = category_counts.get(cat, 0) + 1

    return {
        "total_records": total,
        "flagged_candidates": flagged,
        "flagged_rate": flagged / total if total > 0 else 0.0,
        "category_counts": category_counts,
    }
