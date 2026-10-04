"""
Labeler spot check (review.md B4 / D4): annotation sheet for human review of
the malware labeler's positives.

Run from the project root:
    python -m src.evaluation.labeler_spot_check

Rows
----
(a) The 21 OSV-only positives listed in reports/osv_only_positives.md
    (OSV text regex-positive, GHSA text regex-negative). Recomputed from the
    snapshot and checked against that report's summary table.
(b) 30 DV-positive campaigns from the 142 default (any/any, Section 5.6)
    campaigns, after removing every campaign that contains one of the 21.
    That frame has 12 npm and 33 PyPI campaigns (research_log 5.13), so 15
    npm cannot be drawn: all npm are taken and PyPI fills the sample to 30,
    i.e. 12 npm + 18 PyPI (rule of the 2026-10-04 decision, then 13 + 17).
    Sampling: random.Random(SEED).sample over the PyPI frame sorted by
    (ecosystem, package_name).

For each row the sheet lists every regex match in every regex-positive
record of the displayed package (GHSA and OSV), with CONTEXT_CHARS of
context on each side and the matched span marked with ⟦ ⟧. For a campaign
with several names, the displayed package is the first member name that
has a regex-positive record. The labeler and its patterns are used as is.
No grammar flag and no judgement are printed.

Output: reports/labeler_spot_check.md and results/spot_check_sample.json.
"""

from __future__ import annotations

import json
import random
import re
from pathlib import Path

from src.labeling.malware_labeler import label_batch, label_text
from src.statistics.h1_pilot_analysis import (
    attach_grammar_labels,
    collapse_to_campaign_level,
    select_canonical_record,
)

ROOT = Path(__file__).resolve().parents[2]
SNAPSHOT_PATH = ROOT / "data" / "frozen" / "incidents_snapshot.jsonl"
OSV_ONLY_REPORT = ROOT / "reports" / "osv_only_positives.md"
SHEET_PATH = ROOT / "reports" / "labeler_spot_check.md"
SAMPLE_PATH = ROOT / "results" / "spot_check_sample.json"

SEED = 42
CONTEXT_CHARS = 100
N_SAMPLED = {"npm": 12, "pypi": 18}
# The sheet keeps the 5.13 campaign grouping (research_log 5.14): under the
# 5.14 signature the npm frame falls from 12 to 3 campaigns, and redrawing
# would renumber a sheet that annotators may already be using.
SHEET_SIGNATURE_OPTIONS = dict(use_campaign_tag=False, mask_package_name=False, exclude_generic_tag=False)
ECO_LABEL = {"npm": "npm", "pypi": "PyPI"}

DV = "malware_payload_present_candidate"


# --- Loading -----------------------------------------------------------------

def load_joined(path: Path = SNAPSHOT_PATH) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        records = [json.loads(line) for line in f if line.strip()]
    return attach_grammar_labels(label_batch(records))


def parse_osv_only_report(path: Path = OSV_ONLY_REPORT) -> list[tuple[str, str]]:
    """(ecosystem, package_name) in the report's row order."""
    rows = re.findall(r"^\| \d+ \| `([^`]+)` \| (\w+) \|", path.read_text(encoding="utf-8"), re.M)
    return [(eco.lower(), name) for name, eco in rows]


def osv_only_positives(joined: list[dict]) -> set[tuple[str, str]]:
    """Packages whose canonical GHSA record is regex-negative and which have
    at least one regex-positive OSV record (research_log.md 5.9)."""
    ghsa = {(r["ecosystem"], r["package_name"]): r["malware_label"][DV]
            for r in select_canonical_record(joined, "ghsa") if r["source"] == "ghsa"}
    osv_pos = {(r["ecosystem"], r["package_name"]) for r in joined
               if r["source"] == "osv" and r["malware_label"][DV]}
    return {k for k in osv_pos if k in ghsa and not ghsa[k]}


# --- Sampling ----------------------------------------------------------------

def remaining_positive_campaigns(campaigns: list[dict], exclude: set[tuple[str, str]]) -> dict[str, list[dict]]:
    """DV-positive campaigns with no member in `exclude`, per ecosystem,
    sorted by (ecosystem, package_name) so the draw does not depend on
    snapshot order."""
    frame: dict[str, list[dict]] = {}
    for c in campaigns:
        if not c["malware_label"][DV]:
            continue
        if any((c["ecosystem"], n) in exclude for n in c["_member_package_names"]):
            continue
        frame.setdefault(c["ecosystem"], []).append(c)
    return {eco: sorted(cs, key=lambda c: c["package_name"]) for eco, cs in sorted(frame.items())}


def draw_sample(frame: dict[str, list[dict]], n_per_eco: dict[str, int], seed: int = SEED) -> dict[str, list[dict]]:
    """One Random(seed), ecosystems in sorted order; a stratum whose frame
    is no larger than its n is taken whole (no draw consumed)."""
    rng = random.Random(seed)
    out = {}
    for eco in sorted(n_per_eco):
        cs, n = frame.get(eco, []), n_per_eco[eco]
        if n > len(cs):
            raise ValueError(f"{eco}: asked for {n}, frame has {len(cs)}")
        picked = list(cs) if n == len(cs) else rng.sample(cs, n)
        out[eco] = sorted(picked, key=lambda c: c["package_name"])
    return out


# --- Snippets ----------------------------------------------------------------

def combined_text(record: dict) -> str:
    """Same text label_incident_record() labels."""
    return f"{record.get('summary', '')}\n{record.get('description', '')}"


def snippet(text: str, span: tuple[int, int], context: int = CONTEXT_CHARS) -> str:
    """`context` chars either side of span, matched span in ⟦ ⟧, whitespace
    collapsed, ellipses where the text was cut."""
    s, e = span
    lo, hi = max(0, s - context), min(len(text), e + context)
    out = text[lo:s] + "⟦" + text[s:e] + "⟧" + text[e:hi]
    out = re.sub(r"\s+", " ", out).strip()
    return ("…" if lo > 0 else "") + out + ("…" if hi < len(text) else "")


def record_matches(record: dict) -> list[dict]:
    """Matches of one record, deduplicated on (category, span): two patterns
    of one category hitting the same span are one annotation item."""
    text = combined_text(record)
    seen, out = set(), []
    for m in label_text(text).matches:
        key = (m.category.value, m.span)
        if key in seen:
            continue
        seen.add(key)
        out.append({
            "category": m.category.value,
            "advisory_id": record.get("advisory_id"),
            "source": record.get("source"),
            "snippet": snippet(text, m.span),
        })
    return out


def package_matches(joined: list[dict], eco: str, name: str) -> list[dict]:
    recs = [r for r in joined if r["ecosystem"] == eco and r["package_name"] == name and r["malware_label"][DV]]
    recs.sort(key=lambda r: (r["source"] != "ghsa", r.get("advisory_id") or ""))
    return [m for r in recs for m in record_matches(r)]


def display_package(joined: list[dict], campaign: dict) -> str:
    """First member name with a regex-positive record."""
    positive = {r["package_name"] for r in joined
                if r["ecosystem"] == campaign["ecosystem"] and r["malware_label"][DV]}
    return next(n for n in campaign["_member_package_names"] if n in positive)


# --- Build -------------------------------------------------------------------

def build_rows(joined: list[dict]) -> tuple[list[dict], dict]:
    report_order = parse_osv_only_report()
    computed = osv_only_positives(joined)
    if set(report_order) != computed or len(report_order) != 21:
        raise RuntimeError(f"osv_only_positives.md lists {len(report_order)} packages; "
                           f"snapshot gives {len(computed)}; sets differ: "
                           f"{sorted(set(report_order) ^ computed)}")

    campaigns = collapse_to_campaign_level(joined, **SHEET_SIGNATURE_OPTIONS)
    frame = remaining_positive_campaigns(campaigns, computed)
    sample = draw_sample(frame, N_SAMPLED)

    size_of = {(c["ecosystem"], n): c["_member_count"] for c in campaigns for n in c["_member_package_names"]}
    rows = []
    for eco, name in report_order:
        rows.append({"part": "a", "ecosystem": eco, "package_name": name, "campaign_size": size_of[(eco, name)]})
    for eco in ("npm", "pypi"):
        for c in sample[eco]:
            rows.append({"part": "b", "ecosystem": eco, "package_name": display_package(joined, c),
                         "campaign_size": c["_member_count"]})
    for i, row in enumerate(rows, 1):
        row["row"] = i
        row["matches"] = package_matches(joined, row["ecosystem"], row["package_name"])
        row["categories"] = sorted({m["category"] for m in row["matches"]})
        if not row["matches"]:
            raise RuntimeError(f"row {i} {row['package_name']}: no matches")

    meta = {
        "n_campaigns": len(campaigns),
        "n_dv_positive_campaigns": sum(c["malware_label"][DV] for c in campaigns),
        "frame_sizes": {eco: len(cs) for eco, cs in frame.items()},
    }
    return rows, meta


def render_sheet(rows: list[dict], meta: dict) -> str:
    n_a = sum(r["part"] == "a" for r in rows)
    n_b = len(rows) - n_a
    n_matches = sum(len(r["matches"]) for r in rows)
    fs = meta["frame_sizes"]
    lines = [
        "# Labeler spot check: annotation sheet",
        "",
        f"{len(rows)} packages for human review of the malware labeler's positives "
        f"(review.md B4 / D4). Generated by `python -m src.evaluation.labeler_spot_check` "
        f"from `data/frozen/incidents_snapshot.jsonl`. Sample record: `results/spot_check_sample.json`.",
        "",
        "## What is in the sheet",
        "",
        f"- **Rows 1–{n_a}, part (a):** the {n_a} OSV-only positives of `reports/osv_only_positives.md` "
        "(OSV text regex-positive, GHSA text regex-negative), in that report's order.",
        f"- **Rows {n_a + 1}–{len(rows)}, part (b):** {n_b} DV-positive campaigns, drawn from the "
        f"{meta['n_dv_positive_campaigns']} DV-positive of the {meta['n_campaigns']} Section 5.13 campaigns "
        f"(any/any) after removing every campaign that contains one of the {n_a} above. That leaves {fs.get('npm', 0)} npm and "
        f"{fs.get('pypi', 0)} PyPI campaigns. Fifteen npm cannot be drawn from {fs.get('npm', 0)}, so "
        f"all {N_SAMPLED['npm']} npm are included and {N_SAMPLED['pypi']} PyPI are sampled "
        f"(`random.Random({SEED}).sample` over the PyPI campaigns sorted by name). npm rows come first, "
        "then PyPI, each in alphabetical order.",
        "- **Matches:** every regex match in every regex-positive record (GHSA and OSV) of the package. "
        f"{CONTEXT_CHARS} characters of context on each side, the matched span is in ⟦ ⟧, whitespace "
        "is collapsed, and … marks where the text was cut. Two patterns of one category hitting the "
        f"same span are shown once. {n_matches} matches in total.",
        "- **Campaigns with several names:** the package shown is the first member name with a "
        "regex-positive record. The campaign size is given on the row.",
        "- No grammar flag and no judgement is printed. Fill in **Verdict** and **Note** on each row.",
        "",
        "---",
        "",
    ]
    for r in rows:
        size = f" · campaign of {r['campaign_size']} names" if r["campaign_size"] > 1 else ""
        lines += [
            f"## {r['row']}. `{r['package_name']}`",
            "",
            f"- Ecosystem: {ECO_LABEL[r['ecosystem']]}",
            f"- Part: ({r['part']}){size}",
            f"- Matched categories: {', '.join(r['categories'])}",
            "",
        ]
        for k, m in enumerate(r["matches"], 1):
            lines += [
                f"**Match {k}** · {m['category']} · {m['advisory_id']} ({m['source']})",
                "",
                "```text",
                m["snippet"],
                "```",
                "",
            ]
        lines += ["Verdict:", "", "Note:", "", "---", ""]
    return "\n".join(lines)


def sample_record(rows: list[dict], meta: dict) -> dict:
    return {
        "seed": SEED,
        "rng": "random.Random(seed).sample, PyPI stratum only; frame sorted by package_name",
        "context_chars": CONTEXT_CHARS,
        "setting": {"text_source": "any", "group_on": "any"},
        **meta,
        "n_sampled": N_SAMPLED,
        "note": "npm frame has 12 campaigns, so all 12 are taken (census) and PyPI is 18 to keep 30 rows "
                "in part (b) (rule of the 2026-10-04 decision; research_log 5.13).",
        "n_rows": len(rows),
        "package_names": [r["package_name"] for r in rows],
        "rows": [
            {k: r[k] for k in ("row", "part", "ecosystem", "package_name", "campaign_size", "categories")}
            | {"advisory_ids": sorted({m["advisory_id"] for m in r["matches"]}),
               "n_matches": len(r["matches"])}
            for r in rows
        ],
    }


def main() -> dict:
    rows, meta = build_rows(load_joined())
    SHEET_PATH.write_text(render_sheet(rows, meta), encoding="utf-8")
    record = sample_record(rows, meta)
    SAMPLE_PATH.parent.mkdir(exist_ok=True)
    SAMPLE_PATH.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(f"rows {len(rows)}  matches {sum(len(r['matches']) for r in rows)}  frame {meta['frame_sizes']}")
    print(f"Written: {SHEET_PATH.relative_to(ROOT)}, {SAMPLE_PATH.relative_to(ROOT)}")
    return record


if __name__ == "__main__":
    main()
