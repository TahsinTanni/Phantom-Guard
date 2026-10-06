"""
Annotation sheets for the v2 corpus (research_log 5.18): labeler precision
and recall, each for two annotators.

    python -m src.evaluation.annotation_sheets

Frame: the default (5.18) campaigns of data/frozen/incidents_snapshot_v2.jsonl.
Strata: ecosystem x Amazon Inspector coverage (the reporter indicator that
dominates the label, 5.17). Allocation is proportional to stratum size,
rounded by largest remainder, so the sample is self-weighting up to
rounding. Within a stratum, campaigns are sorted by displayed package name
and drawn with random.Random(SEED).sample, strata in sorted order; each
sheet uses its own Random(SEED).

(a) Precision: N_POSITIVE DV-positive campaigns, excluding every campaign
    that contains one of the 51 packages of the v1 sheet
    (results/spot_check_verdicts.json). Shown as in
    reports/labeler_spot_check.md: every regex match with context.
(b) Recall: N_NEGATIVE DV-negative campaigns, excluding no-text campaigns
    (no text to read; they count as true negatives). Full text shown.
(c) Blank copies of (a) and (b) for a second annotator (*_annotator2.md).

Writes reports/annotation_{precision,recall}_v2[_annotator2].md and
results/annotation_sample_v2.json. The labeler, its patterns and the
grouping are used as is.
"""

from __future__ import annotations

import json
import random
from pathlib import Path

from src.evaluation.labeler_spot_check import (
    CONTEXT_CHARS,
    DV,
    ECO_LABEL,
    combined_text,
    display_package,
    load_joined,
    package_matches,
)
from src.labeling.malware_taxonomy import TAXONOMY
from src.statistics.h1_pilot_analysis import add_reporter_covariates, collapse_to_campaign_level

ROOT = Path(__file__).resolve().parents[2]
SNAPSHOT = ROOT / "data" / "frozen" / "incidents_snapshot_v2.jsonl"
V1_VERDICTS = ROOT / "results" / "spot_check_verdicts.json"
REPORTS = ROOT / "reports"
SAMPLE_PATH = ROOT / "results" / "annotation_sample_v2.json"

SEED = 20261006
N_POSITIVE = 60
N_NEGATIVE = 40

# Same rule as reports/labeler_spot_check.md (research_log 5.15; paper Sec. III-D,
# Data in Brief 4.5).
PRECISION_RULE = (
    "A match counts as **REAL** if the surrounding prose describes the mechanism, as **FALSE** if the "
    "match occurs only in an analyst tag list and not in prose, and as **UNSURE** otherwise. A match is "
    "in a tag list if it lies after a 'Reasons (based on the campaign):' header with no '---' separator "
    "in between. Give one verdict per row: REAL if at least one match on the row is REAL."
)
RECALL_RULE = (
    "The labeler found no mechanism in this text. Verdict **PRESENT** if the prose describes at least one "
    "of the six mechanisms listed above (the labeler missed it), **ABSENT** if it describes none or names "
    "a mechanism only in an analyst tag list and not in prose (same tag-list rule as the precision sheet), "
    "and **UNSURE** otherwise. For PRESENT, name the category or categories in the Note."
)
CATEGORY_LINES = [f"- `{c.value}`" for c in TAXONOMY]


def stratum(c: dict) -> str:
    return f"{c['ecosystem']}|{'amazon' if c['has_amazon_inspector'] else 'no-amazon'}"


def allocate(sizes: dict[str, int], n: int) -> dict[str, int]:
    """Proportional allocation, largest remainder; ties broken by stratum name."""
    total = sum(sizes.values())
    if n > total:
        raise ValueError(f"asked for {n}, frame has {total}")
    quota = {s: n * k / total for s, k in sizes.items()}
    out = {s: int(q) for s, q in quota.items()}
    for s in sorted(quota, key=lambda s: (-(quota[s] - out[s]), s))[: n - sum(out.values())]:
        out[s] += 1
    return out


def draw(frame: list[dict], n: int, seed: int = SEED) -> tuple[list[dict], dict, dict]:
    by: dict[str, list[dict]] = {}
    for c in frame:
        by.setdefault(c["stratum"], []).append(c)
    sizes = {s: len(cs) for s, cs in sorted(by.items())}
    alloc = allocate(sizes, n)
    rng = random.Random(seed)
    picked = []
    for s in sorted(by):
        cs = sorted(by[s], key=lambda c: c["display"])
        k = alloc[s]
        picked += cs if k == len(cs) else rng.sample(cs, k)
    picked.sort(key=lambda c: (c["ecosystem"], c["stratum"], c["display"]))
    return picked, sizes, alloc


def build():
    joined = load_joined(SNAPSHOT)
    campaigns = add_reporter_covariates(collapse_to_campaign_level(joined))
    v1_packages = {r["package"] for r in json.loads(V1_VERDICTS.read_text())["rows"]}
    for c in campaigns:
        c["stratum"] = stratum(c)
        if c["malware_label"][DV]:
            c["display"] = display_package(joined, c)
        else:
            c["display"] = c["_member_package_names"][0]

    pos_frame = [c for c in campaigns if c["malware_label"][DV]
                 and not set(c["_member_package_names"]) & v1_packages]
    neg_frame = [c for c in campaigns if not c["malware_label"][DV] and not c["no_text"]]
    pos, pos_sizes, pos_alloc = draw(pos_frame, N_POSITIVE)
    neg, neg_sizes, neg_alloc = draw(neg_frame, N_NEGATIVE)

    pos_rows = []
    for i, c in enumerate(pos, 1):
        matches = package_matches(joined, c["ecosystem"], c["display"])
        if not matches:
            raise RuntimeError(f"positive row {i} {c['display']}: no matches")
        pos_rows.append({"row": i, "c": c, "matches": matches,
                         "categories": sorted({m["category"] for m in matches})})
    neg_rows = []
    for i, c in enumerate(neg, 1):
        recs = sorted((r for r in joined if r["ecosystem"] == c["ecosystem"] and r["package_name"] == c["display"]),
                      key=lambda r: (r["source"] != "ghsa", r.get("advisory_id") or ""))
        neg_rows.append({"row": i, "c": c, "records": recs})

    meta = {
        "snapshot": str(SNAPSHOT.relative_to(ROOT)),
        "seed": SEED,
        "rng": "random.Random(seed).sample per stratum, strata sorted, frame sorted by displayed package; "
               "one Random(seed) per sheet",
        "strata": "ecosystem x amazon_inspector coverage",
        "n_campaigns": len(campaigns),
        "n_dv_positive": sum(bool(c["malware_label"][DV]) for c in campaigns),
        "n_dv_negative": sum(not c["malware_label"][DV] for c in campaigns),
        "n_no_text": sum(c["no_text"] for c in campaigns),
        "precision": {"frame": len(pos_frame), "excluded_v1_campaigns":
                      sum(1 for c in campaigns if c["malware_label"][DV]) - len(pos_frame),
                      "stratum_sizes": pos_sizes, "allocation": pos_alloc},
        "recall": {"frame": len(neg_frame), "excluded_no_text": sum(c["no_text"] for c in campaigns),
                   "stratum_sizes": neg_sizes, "allocation": neg_alloc},
    }
    return pos_rows, neg_rows, meta


def _header(title: str, annotator: int, intro: list[str], rule: str, extra: list[str]) -> list[str]:
    return [
        f"# {title}" + (" (annotator 2)" if annotator == 2 else ""),
        "",
        *intro,
        "",
        "## Rule",
        "",
        rule,
        "",
        *extra,
        "- No grammar flag and no judgement is printed. Fill in **Verdict** and **Note** on each row. "
        "Annotate without looking at the other annotator's sheet.",
        "",
        "---",
        "",
    ]


def render_precision(rows: list[dict], meta: dict, annotator: int) -> str:
    m = meta["precision"]
    strata = ", ".join(f"{s} {m['allocation'][s]}/{m['stratum_sizes'][s]}" for s in m["stratum_sizes"])
    lines = _header(
        "Labeler precision: annotation sheet (v2)", annotator,
        [f"{len(rows)} labeler-positive campaigns of `{meta['snapshot']}` for human review of the malware "
         "labeler's positives. Generated by `python -m src.evaluation.annotation_sheets`; sample record "
         "`results/annotation_sample_v2.json`. Same format and rule as `reports/labeler_spot_check.md`."],
        PRECISION_RULE,
        ["## What is in the sheet", "",
         f"- **Frame:** the {m['frame']} DV-positive campaigns (of {meta['n_dv_positive']}) that contain none of "
         f"the 51 packages of the v1 sheet ({m['excluded_v1_campaigns']} campaigns excluded).",
         f"- **Sample:** stratified by ecosystem × Amazon Inspector coverage, proportional allocation, "
         f"`random.Random({SEED})`. Drawn/frame per stratum: {strata}. Rows are ordered by ecosystem, "
         "stratum, then package name.",
         f"- **Matches:** every regex match in every regex-positive record (GHSA and OSV) of the package. "
         f"{CONTEXT_CHARS} characters of context on each side, the matched span is in ⟦ ⟧, whitespace "
         "is collapsed, and … marks where the text was cut. Two patterns of one category hitting the same "
         f"span are shown once. {sum(len(r['matches']) for r in rows)} matches in total.",
         "- **Campaigns with several names:** the package shown is the first member name with a "
         "regex-positive record. The campaign size is given on the row."])
    for r in rows:
        c = r["c"]
        size = f" · campaign of {c['_member_count']} names" if c["_member_count"] > 1 else ""
        lines += [f"## {r['row']}. `{c['display']}`", "",
                  f"- Ecosystem: {ECO_LABEL[c['ecosystem']]}{size}",
                  f"- Matched categories: {', '.join(r['categories'])}", ""]
        for k, mt in enumerate(r["matches"], 1):
            lines += [f"**Match {k}** · {mt['category']} · {mt['advisory_id']} ({mt['source']})", "",
                      "```text", mt["snippet"], "```", ""]
        lines += ["Verdict:", "", "Note:", "", "---", ""]
    return "\n".join(lines)


def render_recall(rows: list[dict], meta: dict, annotator: int) -> str:
    m = meta["recall"]
    strata = ", ".join(f"{s} {m['allocation'][s]}/{m['stratum_sizes'][s]}" for s in m["stratum_sizes"])
    lines = _header(
        "Labeler recall: annotation sheet (v2)", annotator,
        [f"{len(rows)} labeler-negative campaigns of `{meta['snapshot']}` for an estimate of what the malware "
         "labeler misses. Generated by `python -m src.evaluation.annotation_sheets`; sample record "
         "`results/annotation_sample_v2.json`. The six mechanisms:", "", *CATEGORY_LINES],
        RECALL_RULE,
        ["## What is in the sheet", "",
         f"- **Frame:** the {m['frame']} DV-negative campaigns (of {meta['n_dv_negative']}) that are not no-text "
         f"({m['excluded_no_text']} no-text campaigns excluded: their only text is the OpenSSF credit link).",
         f"- **Sample:** stratified by ecosystem × Amazon Inspector coverage, proportional allocation, "
         f"`random.Random({SEED})`. Drawn/frame per stratum: {strata}. Rows are ordered by ecosystem, "
         "stratum, then package name.",
         "- **Text:** the full summary and description of every record (GHSA first, then OSV) of the "
         "package shown, which is the campaign's first member. This is the text the labeler read."])
    for r in rows:
        c = r["c"]
        size = f" · campaign of {c['_member_count']} names" if c["_member_count"] > 1 else ""
        lines += [f"## {r['row']}. `{c['display']}`", "", f"- Ecosystem: {ECO_LABEL[c['ecosystem']]}{size}", ""]
        for rec in r["records"]:
            lines += [f"**{rec.get('advisory_id')}** ({rec.get('source')})", "",
                      "````text", combined_text(rec).strip(), "````", ""]
        lines += ["Verdict:", "", "Note:", "", "---", ""]
    return "\n".join(lines)


def sample_record(pos_rows, neg_rows, meta) -> dict:
    def row(r, kind):
        c = r["c"]
        out = {"row": r["row"], "ecosystem": c["ecosystem"], "package_name": c["display"], "stratum": c["stratum"],
               "campaign_members": c["_member_package_names"]}
        if kind == "pos":
            out |= {"categories": r["categories"], "n_matches": len(r["matches"])}
        else:
            out |= {"advisory_ids": [x.get("advisory_id") for x in r["records"]]}
        return out
    return {**meta, "precision_rows": [row(r, "pos") for r in pos_rows],
            "recall_rows": [row(r, "neg") for r in neg_rows]}


def main() -> dict:
    pos_rows, neg_rows, meta = build()
    for annotator, suffix in ((1, ""), (2, "_annotator2")):
        (REPORTS / f"annotation_precision_v2{suffix}.md").write_text(
            render_precision(pos_rows, meta, annotator), encoding="utf-8")
        (REPORTS / f"annotation_recall_v2{suffix}.md").write_text(
            render_recall(neg_rows, meta, annotator), encoding="utf-8")
    record = sample_record(pos_rows, neg_rows, meta)
    SAMPLE_PATH.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(f"precision rows {len(pos_rows)} {meta['precision']['allocation']}")
    print(f"recall rows {len(neg_rows)} {meta['recall']['allocation']}")
    print("Written: reports/annotation_{precision,recall}_v2[_annotator2].md, results/annotation_sample_v2.json")
    return record


if __name__ == "__main__":
    main()
