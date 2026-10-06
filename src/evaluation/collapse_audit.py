"""
Campaign-collapse audit: the largest campaigns, under-merge candidates and
over-merge candidates, for human review.

    python -m src.evaluation.collapse_audit                      # v1 snapshot
    python -m src.evaluation.collapse_audit \
        --snapshot data/frozen/incidents_snapshot_v2.jsonl \
        --out reports/collapse_audit_v2.md

Uses the 5.14 signature rules unchanged (collapse_to_campaign_level with
default settings). Campaign ids are the C001.. ids of campaign_table_rows,
so they match results/campaigns.csv for the same snapshot.

Candidates:
- under-merge: two campaigns of one ecosystem whose masked text prefixes
  (signature_text: headers stripped, own name and URLs masked) agree
  on the first UNDER_SHORT characters but not on the first UNDER_LONG;
- over-merge: a campaign with 2+ members in which some pair of members'
  texts has token Jaccard below OVER_JACCARD (the worst pair is shown).
Each row has a 100-character excerpt per side and a blank decision column.
Reads only the snapshot; writes only --out.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from itertools import combinations
from pathlib import Path

from src.labeling.malware_labeler import label_batch
from src.statistics.h1_pilot_analysis import (
    _name_level_record,
    attach_grammar_labels,
    build_campaign_signature,
    campaign_table_rows,
    collapse_to_campaign_level,
    signature_text,
)

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SNAPSHOT = ROOT / "data" / "frozen" / "incidents_snapshot.jsonl"
DEFAULT_OUT = ROOT / "reports" / "collapse_audit_v1.md"

N_LARGEST = 25
UNDER_SHORT, UNDER_LONG = 120, 200
OVER_JACCARD = 0.5
EXCERPT = 100
OUTCOME = ("malware_label", "malware_payload_present_candidate")
_TOKEN = re.compile(r"\w+")


def masked_text(record: dict) -> str:
    """The text build_campaign_signature() slices for a text-prefix key
    (signature_text: headers stripped, name masked, URLs masked)."""
    return signature_text(record)


def tokens(text: str) -> set[str]:
    return set(_TOKEN.findall(text.lower()))


def jaccard(a: set[str], b: set[str]) -> float:
    return len(a & b) / len(a | b) if a | b else 1.0


def diverge_at(a: str, b: str) -> int:
    """Offset of the first character where `a` and `b` differ."""
    return next((i for i, (x, y) in enumerate(zip(a, b)) if x != y), min(len(a), len(b)))


def excerpt(text: str, start: int = 0) -> str:
    """EXCERPT characters from `start`; a divergence in the first 20
    characters is shown from the beginning of the text instead."""
    start = start if start >= 20 else 0
    s = " ".join(text[start:start + EXCERPT].split())
    return s.replace("|", "\\|")


def build(snapshot: Path):
    records = [json.loads(l) for l in snapshot.read_text(encoding="utf-8").splitlines() if l.strip()]
    joined = attach_grammar_labels(label_batch(records))

    # Stage 1 and 2 exactly as collapse_to_campaign_level(), keeping the
    # name-level records so every member's own text is available.
    by_name: dict[tuple[str, str], list[dict]] = {}
    for r in joined:
        by_name.setdefault((r["ecosystem"], r["package_name"]), []).append(r)
    name_level = [_name_level_record(m, "any", "any", *OUTCOME) for m in by_name.values()]
    groups: dict[tuple[str, str], list[dict]] = {}
    for r in name_level:
        groups.setdefault(build_campaign_signature(r), []).append(r)

    campaigns = collapse_to_campaign_level(joined)
    rows = campaign_table_rows(campaigns)
    members = list(groups.values())
    assert [[m["package_name"] for m in g] for g in members] == \
        [c["_member_package_names"] for c in campaigns], "collapse order drifted"
    return records, rows, members


def under_merge(rows, members):
    reps = [masked_text(g[0]) for g in members]
    out = []
    for i, j in combinations(range(len(rows)), 2):
        if rows[i]["ecosystem"] != rows[j]["ecosystem"]:
            continue
        a, b = reps[i], reps[j]
        if len(a) >= UNDER_SHORT and a[:UNDER_SHORT] == b[:UNDER_SHORT] and a[:UNDER_LONG] != b[:UNDER_LONG]:
            out.append((rows[i], rows[j], diverge_at(a, b), a, b))
    return out


def over_merge(rows, members):
    out = []
    for row, g in zip(rows, members):
        if len(g) < 2:
            continue
        texts = [masked_text(m) for m in g]
        toks = [tokens(t) for t in texts]
        worst = min(((jaccard(toks[x], toks[y]), x, y) for x, y in combinations(range(len(g)), 2)))
        if worst[0] < OVER_JACCARD:
            j, x, y = worst
            n_low = sum(1 for p, q in combinations(range(len(g)), 2) if jaccard(toks[p], toks[q]) < OVER_JACCARD)
            out.append((row, j, n_low, len(g) * (len(g) - 1) // 2,
                        g[x]["package_name"], g[y]["package_name"], texts[x], texts[y]))
    return out


def render(snapshot: Path, records, rows, members, under, over) -> str:
    sig = Counter(r["signature_type"] for r in rows)
    eco = Counter(r["ecosystem"] for r in rows)
    pk = Counter(r["ecosystem"] for g in members for r in g)
    lines = [
        f"# Campaign-collapse audit: `{snapshot.relative_to(ROOT)}`",
        "",
        "Generated by `python -m src.evaluation.collapse_audit"
        + ("" if snapshot == DEFAULT_SNAPSHOT else f" --snapshot {snapshot.relative_to(ROOT)}")
        + "`. Signature rules unchanged (research_log 5.14). Fill in the *decision* column "
        "(e.g. merge / keep / split); nothing here changes the grouping.",
        "",
        f"- Records {len(records)}; packages {sum(pk.values())} (npm {pk['npm']}, pypi {pk['pypi']}); "
        f"campaigns {len(rows)} (npm {eco['npm']}, pypi {eco['pypi']}).",
        f"- Signature types: " + ", ".join(f"{k} {v}" for k, v in sorted(sig.items())) + ".",
        f"- Under-merge candidates: {len(under)} pairs (masked prefixes equal on the first "
        f"{UNDER_SHORT} characters, different within {UNDER_LONG}).",
        f"- Over-merge candidates: {len(over)} campaigns (some member pair with token Jaccard "
        f"< {OVER_JACCARD}; tokens = lower-cased `\\w+` of the masked, header-stripped text).",
        "",
        f"## 1. The {N_LARGEST} largest campaigns",
        "",
        "| # | Campaign | Ecosystem | Signature | Members | Member names |",
        "|---|---|---|---|---|---|",
    ]
    ranked = sorted(zip(rows, members), key=lambda t: (-len(t[1]), t[0]["campaign_id"]))
    for n, (row, g) in enumerate(ranked[:N_LARGEST], 1):
        names = ", ".join(f"`{m['package_name']}`" for m in g)
        lines.append(f"| {n} | {row['campaign_id']} | {row['ecosystem']} | {row['signature_type']} | {len(g)} | {names} |")

    lines += [
        "",
        "## 2. Under-merge candidates",
        "",
        "Excerpts start at the first differing character. *Diverge at* is that character's offset.",
        "",
        "| # | Campaign A | Campaign B | Ecosystem | Signatures | Sizes | Diverge at | Excerpt A | Excerpt B | Decision |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    if not under:
        lines.append("| — | none | | | | | | | | |")
    for n, (ra, rb, k, a, b) in enumerate(under, 1):
        sa = len(members[rows.index(ra)]); sb = len(members[rows.index(rb)])
        lines.append(f"| {n} | {ra['campaign_id']} | {rb['campaign_id']} | {ra['ecosystem']} | "
                     f"{ra['signature_type']} / {rb['signature_type']} | {sa} / {sb} | {k} | "
                     f"{excerpt(a, k)} | {excerpt(b, k)} | |")

    lines += [
        "",
        "## 3. Over-merge candidates",
        "",
        "The worst-matching member pair is shown; *low pairs* counts member pairs below the threshold. "
        "Excerpts start at the first differing character (*Diverge at*).",
        "",
        "| # | Campaign | Ecosystem | Signature | Members | Worst Jaccard | Low pairs | Member A | Member B | Diverge at | Excerpt A | Excerpt B | Decision |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    if not over:
        lines.append("| — | none | | | | | | | | | | | |")
    for n, (row, j, n_low, n_pairs, pa, pb, ta, tb) in enumerate(over, 1):
        size = len(members[rows.index(row)])
        lines.append(f"| {n} | {row['campaign_id']} | {row['ecosystem']} | {row['signature_type']} | {size} | "
                     f"{j:.2f} | {n_low}/{n_pairs} | `{pa}` | `{pb}` | {(k := diverge_at(ta, tb))} | "
                     f"{excerpt(ta, k)} | {excerpt(tb, k)} | |")
    return "\n".join(lines) + "\n"


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--snapshot", type=Path, default=DEFAULT_SNAPSHOT)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = ap.parse_args(argv)
    snapshot = (args.snapshot if args.snapshot.is_absolute() else ROOT / args.snapshot).resolve()
    out = args.out if args.out.is_absolute() else ROOT / args.out

    records, rows, members = build(snapshot)
    under, over = under_merge(rows, members), over_merge(rows, members)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render(snapshot, records, rows, members, under, over), encoding="utf-8")
    print(f"campaigns {len(rows)}  under-merge pairs {len(under)}  over-merge campaigns {len(over)}")
    print(f"Written: {out}")


if __name__ == "__main__":
    main()
