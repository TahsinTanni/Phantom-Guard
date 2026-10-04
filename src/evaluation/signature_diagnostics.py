"""
Research_log 5.14 diagnostics: what the campaign-signature changes and the
narrowed negation filter each do on the frozen snapshot.

    python -m src.evaluation.signature_diagnostics

Prints (1) campaign counts under each signature switch, (2) campaigns the
kam193 "Campaign:" key merges that the text prefix did not and vice versa,
(3) the amel10 family check and a split check for name masking, and (4)
match drops per negation cue, under the 5.13 cue list and the 5.14 one.
Reads only the snapshot; writes nothing.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

from src.labeling.malware_labeler import (
    NEGATION_WINDOW,
    label_batch,
    negation_cue,
)
from src.labeling.malware_taxonomy import TAXONOMY
from src.statistics.h1_pilot_analysis import (
    attach_grammar_labels,
    collapse_to_campaign_level,
)

SNAPSHOT = Path(__file__).resolve().parents[2] / "data" / "frozen" / "incidents_snapshot.jsonl"

# The 10 packages whose GHSA text names the npm account amel10
# (labeler_spot_check.md before 5.13, rows 23-28, 30, 32-34).
AMEL10 = (
    "ai-workshop-maa15-radio", "ai-workshop-radio-app", "ai-workshop-radio-lambda",
    "alexa-cybertron-team-code-review-agent", "apl-rive-renderer", "brioche-apl-dev-env",
    "figma-to-apl", "live-detection-dashboard", "niksinnkatalapp", "okra-cloud-cdk",
)

# 5.13 cue list and rule (no clause-break check), for the drop comparison.
CUES_5_13 = re.compile(
    r"\b(?:does not|do not|did not|doesn't|no evidence of|without|rather than)\b",
    flags=re.IGNORECASE,
)

SETTINGS = {
    "5.13 (all off)": dict(use_campaign_tag=False, mask_package_name=False, exclude_generic_tag=False),
    "GENERIC exclusion only": dict(use_campaign_tag=False, mask_package_name=False, exclude_generic_tag=True),
    "Campaign tag only": dict(use_campaign_tag=True, mask_package_name=False, exclude_generic_tag=False),
    "name mask only": dict(use_campaign_tag=False, mask_package_name=True, exclude_generic_tag=False),
    "prefix (GENERIC + mask, no tag)": dict(use_campaign_tag=False, mask_package_name=True, exclude_generic_tag=True),
    "5.14 (all on)": dict(use_campaign_tag=True, mask_package_name=True, exclude_generic_tag=True),
}


def load_records() -> list[dict]:
    return [json.loads(l) for l in SNAPSHOT.read_text(encoding="utf-8").splitlines() if l.strip()]


def partition(campaigns: list[dict]) -> list[frozenset]:
    return [frozenset((c["ecosystem"], n) for n in c["_member_package_names"]) for c in campaigns]


def merges_not_in(fine: list[frozenset], coarse: list[frozenset]) -> list[list[frozenset]]:
    """Groups of `coarse` that join two or more groups of `fine`, each given
    as the list of `fine` groups it joins."""
    out = []
    for g in coarse:
        parts = [f for f in fine if f & g]
        if len(parts) > 1:
            out.append(parts)
    return out


def _counts(campaigns: list[dict]) -> str:
    eco = Counter(c["ecosystem"] for c in campaigns)
    return f"pooled {len(campaigns)}  npm {eco['npm']}  pypi {eco['pypi']}"


def _fmt(group: frozenset) -> str:
    names = sorted(n for _, n in group)
    return f"{names[0]} ({len(names)})"


def negation_drops(records: list[dict]) -> tuple[Counter, Counter]:
    """Match drops per cue across all records' summary + description text:
    (5.13 rule, 5.14 rule). Under 5.13 the first cue in the window is
    credited, as re.search found it."""
    old, new = Counter(), Counter()
    for r in records:
        text = f"{r.get('summary', '')}\n{r.get('description', '')}"
        for definition in TAXONOMY.values():
            for pattern in definition.patterns:
                for m in re.finditer(pattern, text, flags=re.IGNORECASE):
                    hit = CUES_5_13.search(text[max(0, m.start() - NEGATION_WINDOW):m.start()])
                    if hit:
                        old[hit.group(0).lower()] += 1
                    cue = negation_cue(text, m.start())
                    if cue:
                        new[cue] += 1
    return old, new


def main() -> None:
    records = load_records()
    joined = attach_grammar_labels(label_batch(records))

    print("1. Campaign counts by signature setting (text any, group any)")
    parts = {}
    for label, opts in SETTINGS.items():
        campaigns = collapse_to_campaign_level(joined, **opts)
        parts[label] = partition(campaigns)
        print(f"  {label:34s} {_counts(campaigns)}")

    print("\n2. Campaign tag key vs text prefix (both with GENERIC exclusion and name mask)")
    prefix, full = parts["prefix (GENERIC + mask, no tag)"], parts["5.14 (all on)"]
    tag_only = merges_not_in(prefix, full)
    prefix_only = merges_not_in(full, prefix)
    print(f"  tag merges the prefix did not: {len(tag_only)} campaigns, "
          f"{sum(len(p) for p in tag_only)} prefix groups -> {len(tag_only)}")
    for p in tag_only:
        print("    " + " + ".join(_fmt(g) for g in p))
    print(f"  prefix merges the tag did not: {len(prefix_only)} campaigns, "
          f"{sum(len(p) for p in prefix_only)} tag-keyed groups -> {len(prefix_only)}")
    for p in prefix_only:
        print("    " + " + ".join(_fmt(g) for g in p))

    print("\n3. Name mask")
    for g in full:
        if any(n in AMEL10 for _, n in g):
            print(f"  amel10 group in 5.14: {sorted(n for _, n in g)}")
    missing = set(AMEL10) - {n for g in full for _, n in g}
    print(f"  amel10 names absent from snapshot: {sorted(missing) or 'none'}")
    for before, after in (("5.13 (all off)", "name mask only"),
                          ("prefix (GENERIC + mask, no tag)", "5.14 (all on)"),
                          ("5.13 (all off)", "5.14 (all on)")):
        splits = merges_not_in(parts[after], parts[before])
        print(f"  groups of [{before}] split in [{after}]: {len(splits)}")
        for p in splits:
            print("    " + " | ".join(_fmt(g) for g in p))
    mask_merges = merges_not_in(parts["5.13 (all off)"], parts["name mask only"])
    print(f"  merges made by the name mask alone: {len(mask_merges)}")
    for p in mask_merges:
        print("    " + " + ".join(_fmt(g) for g in p))

    print("\n4. Negation: match drops per cue, all 401 records")
    old, new = negation_drops(records)
    print(f"  {'cue':16s} {'5.13':>5} {'5.14':>5}")
    for cue in sorted(set(old) | set(new) | {"without", "rather than"}):
        print(f"  {cue:16s} {old[cue]:5d} {new[cue]:5d}")
    print(f"  {'total':16s} {sum(old.values()):5d} {sum(new.values()):5d}")


if __name__ == "__main__":
    main()
