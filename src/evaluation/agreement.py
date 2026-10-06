"""
Inter-annotator agreement and labeler precision / recall from the v2
annotation sheets (research_log 5.18).

    python -m src.evaluation.agreement            # the four v2 sheets

Reads the filled sheets written by src/evaluation/annotation_sheets.py
(annotator 1 and annotator 2, precision and recall) plus
results/annotation_sample_v2.json, and writes results/agreement_v2.json.

- Cohen's kappa per sheet, over rows both annotators filled.
- Precision per annotator: REAL / (REAL + FALSE), UNSURE excluded, and
  REAL / all rows with UNSURE counted as FALSE; Wilson 95% CIs.
- Miss rate per annotator: PRESENT / (PRESENT + ABSENT) on the recall sheet
  (labeler negatives), UNSURE excluded; Wilson 95% CI.
- Recall per annotator: estimated true positives over estimated true
  positives plus false negatives, over all campaigns:
      recall = N_pos * precision / (N_pos * precision + N_neg * miss_rate)
  with N_pos the DV-positive campaigns and N_neg the recall frame (no-text
  campaigns are DV-negative with no text, so they add no misses). Recall is
  not a single proportion, so its interval is formed from the Wilson bounds
  of precision and miss rate (lower: low precision, high miss rate; upper:
  the reverse). It is conservative, not an exact 95% interval.
- Disagreement list: every row whose two verdicts differ, with both notes.
The same functions also parse reports/labeler_spot_check.md.

Adjudicated labeler report (research_log 5.18; labeler_report(), written to
results/labeler_agreement_v2.json): kappa on the first-pass "Verdict:" lines;
labeler precision (REAL / (REAL + FALSE)) and miss rate (PRESENT / all rows)
on annotator 1's "Adjudicated:" lines; precision per matched category and
miss counts per stratum; the disagreement list with the adjudicated verdict;
the matched spans of every FALSE row with a tag-list check (labeler rerun on
the frozen snapshot); categories named in the notes of every PRESENT row;
ABSENT rows adjudicated as host-fingerprint sending only. A row with no
"Adjudicated:" line takes the first-pass verdict when both annotators agree
and is flagged; otherwise it is left out and flagged.
"""

from __future__ import annotations

import argparse
import json
import math
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REPORTS = ROOT / "reports"
SAMPLE = ROOT / "results" / "annotation_sample_v2.json"
OUT = ROOT / "results" / "agreement_v2.json"

PRECISION_LABELS = ("REAL", "FALSE", "UNSURE")
RECALL_LABELS = ("PRESENT", "ABSENT", "UNSURE")
_ROW = re.compile(r"^## (\d+)\. `([^`]+)`\s*$", re.M)
_VERDICT = re.compile(r"^Verdict:[ \t]*(.*?)[ \t]*$", re.M)
_NOTE = re.compile(r"^Note:[ \t]*(.*?)[ \t]*$", re.M)
_ADJUDICATED = re.compile(r"^Adjudicated:[ \t]*(.*?)[ \t]*$", re.M)
_ADJ_NOTE = re.compile(r"^Adjudication note:[ \t]*(.*?)[ \t]*$", re.M)
# Quoted advisory text sits in ``` or ```` fences and may itself contain a
# "Verdict:" or "Note:" line; fences are removed before the search.
_FENCE = re.compile(r"^(`{3,})[^\n]*\n.*?^\1[ \t]*$", re.M | re.S)


# --- Parsing -----------------------------------------------------------------

def parse_sheet(text: str, labels: tuple[str, ...] | None = None) -> list[dict]:
    """One dict per row: row, package, verdict (upper-cased, None if blank),
    note. A verdict outside `labels` raises ValueError."""
    heads = list(_ROW.finditer(text))
    rows = []
    for i, h in enumerate(heads):
        body = _FENCE.sub("", text[h.end(): heads[i + 1].start() if i + 1 < len(heads) else len(text)])
        v, n = _VERDICT.search(body), _NOTE.search(body)
        adj, adj_note = _ADJUDICATED.search(body), _ADJ_NOTE.search(body)
        verdict = (v.group(1).strip().upper() or None) if v else None
        adjudicated = (adj.group(1).strip().upper() or None) if adj else None
        for name, value in (("verdict", verdict), ("adjudicated", adjudicated)):
            if value and labels and value not in labels:
                raise ValueError(f"row {h.group(1)}: {name} {value!r} not in {labels}")
        rows.append({"row": int(h.group(1)), "package": h.group(2), "verdict": verdict,
                     "note": (n.group(1).strip() if n else ""),
                     "adjudicated": adjudicated,
                     "adjudication_note": (adj_note.group(1).strip() if adj_note else None)})
    return rows


def read_sheet(path: Path, labels: tuple[str, ...]) -> list[dict]:
    return parse_sheet(Path(path).read_text(encoding="utf-8"), labels)


# --- Statistics --------------------------------------------------------------

def wilson(k: int, n: int, z: float = 1.959963984540054) -> tuple[float, float] | None:
    if n == 0:
        return None
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def proportion(k: int, n: int) -> dict:
    return {"k": k, "n": n, "p": (k / n if n else None), "wilson95": wilson(k, n)}


def cohen_kappa(a: list[str], b: list[str]) -> float | None:
    """Cohen's kappa for two equal-length lists of nominal labels. None when
    chance agreement is 1 (both annotators used one and the same label)."""
    if len(a) != len(b):
        raise ValueError("label lists differ in length")
    n = len(a)
    if n == 0:
        return None
    po = sum(x == y for x, y in zip(a, b)) / n
    ca, cb = Counter(a), Counter(b)
    pe = sum(ca[k] * cb[k] for k in set(ca) | set(cb)) / (n * n)
    return None if pe == 1 else (po - pe) / (1 - pe)


def paired(rows_a: list[dict], rows_b: list[dict]) -> list[tuple[dict, dict]]:
    """Rows matched on (row, package); both sheets must list the same rows."""
    key_a = [(r["row"], r["package"]) for r in rows_a]
    key_b = [(r["row"], r["package"]) for r in rows_b]
    if key_a != key_b:
        raise ValueError("the two sheets do not list the same rows")
    return list(zip(rows_a, rows_b))


def agreement(rows_a: list[dict], rows_b: list[dict]) -> dict:
    pairs = paired(rows_a, rows_b)
    both = [(a, b) for a, b in pairs if a["verdict"] and b["verdict"]]
    return {
        "n_rows": len(pairs),
        "n_both_filled": len(both),
        "percent_agreement": (sum(a["verdict"] == b["verdict"] for a, b in both) / len(both)) if both else None,
        "cohen_kappa": cohen_kappa([a["verdict"] for a, _ in both], [b["verdict"] for _, b in both]),
        "disagreements": [
            {"row": a["row"], "package": a["package"], "annotator1": a["verdict"], "annotator2": b["verdict"],
             "note1": a["note"], "note2": b["note"]}
            for a, b in both if a["verdict"] != b["verdict"]
        ],
    }


def precision(rows: list[dict]) -> dict:
    c = Counter(r["verdict"] for r in rows if r["verdict"])
    filled = sum(c.values())
    return {"counts": dict(c), "n_filled": filled, "n_rows": len(rows),
            "excluding_unsure": proportion(c["REAL"], c["REAL"] + c["FALSE"]),
            "unsure_as_false": proportion(c["REAL"], filled)}


def miss_rate(rows: list[dict]) -> dict:
    c = Counter(r["verdict"] for r in rows if r["verdict"])
    return {"counts": dict(c), "n_filled": sum(c.values()), "n_rows": len(rows),
            "excluding_unsure": proportion(c["PRESENT"], c["PRESENT"] + c["ABSENT"])}


def recall_estimate(n_pos: int, prec: dict, n_neg: int, miss: dict) -> dict:
    """Recall from precision (on labeler positives) and miss rate (on labeler
    negatives); interval from the two Wilson bounds (see module docstring)."""
    p, m = prec["p"], miss["p"]
    if p is None or m is None:
        return {"recall": None, "interval": None}

    def r(pp, mm):
        tp, fn = n_pos * pp, n_neg * mm
        return tp / (tp + fn) if tp + fn else None

    (p_lo, p_hi), (m_lo, m_hi) = prec["wilson95"], miss["wilson95"]
    return {"recall": r(p, m), "interval": (r(p_lo, m_hi), r(p_hi, m_lo)),
            "est_true_positives": n_pos * p, "est_false_negatives": n_neg * m,
            "n_pos": n_pos, "n_neg": n_neg,
            "interval_method": "Wilson bounds of precision and miss rate combined (conservative)"}


# --- Adjudicated labeler report ----------------------------------------------

LABELER_OUT = ROOT / "results" / "labeler_agreement_v2.json"
SNAPSHOT_V2 = ROOT / "data" / "frozen" / "incidents_snapshot_v2.jsonl"
RECALL_CATEGORIES = ROOT / "data" / "recall_categories_v2.json"
TAG_LIST_HEADER = "Reasons (based on the campaign):"
# ABSENT rows whose adjudication note gives host-fingerprint sending as the
# only behaviour (hostname / IP / username / OS / host id beacon).
_HOST_FINGERPRINT = re.compile(r"host[ -]?(?:fingerprint|id\b|ids\b|-id)|phone-home", re.I)
# Annotator notes that mention host-information sending (for review lists).
_HOST_INFO = re.compile(r"host[- ]information|host info|hostname|whoami|\bIP\b|username|host ids?", re.I)


def final_verdict(a: dict, b: dict) -> tuple[str | None, str]:
    """Annotator 1's adjudicated verdict; without one, the first-pass
    verdict if both annotators agree. Returns (verdict, source)."""
    if a.get("adjudicated"):
        return a["adjudicated"], "adjudicated"
    if a["verdict"] and a["verdict"] == b["verdict"]:
        return a["verdict"], "first-pass consensus (no Adjudicated line)"
    return None, "missing (no Adjudicated line, first pass disagrees)"


def in_tag_list(text: str, start: int) -> bool:
    """research_log 5.15 definition: the span lies after a 'Reasons (based on
    the campaign):' header with no '---' separator in between."""
    before = text[:start]
    i = before.rfind(TAG_LIST_HEADER)
    return i >= 0 and "---" not in before[i:]


def row_spans(records: list[dict], ecosystem: str, package: str) -> list[dict]:
    """Every labeler match in the package's regex-positive records, with the
    matched span quoted and the tag-list check. Labeler used as is."""
    from src.labeling.malware_labeler import label_text

    out, seen = [], set()
    recs = sorted((r for r in records if r["ecosystem"] == ecosystem and r["package_name"] == package),
                  key=lambda r: (r["source"] != "ghsa", r.get("advisory_id") or ""))
    for r in recs:
        text = f"{r.get('summary', '')}\n{r.get('description', '')}"
        for m in label_text(text).matches:
            key = (r.get("advisory_id"), m.category.value, m.span)
            if key in seen:
                continue
            seen.add(key)
            out.append({"advisory_id": r.get("advisory_id"), "source": r.get("source"),
                        "category": m.category.value, "span": " ".join(text[m.span[0]:m.span[1]].split()),
                        "in_tag_list": in_tag_list(text, m.span[0])})
    return out


def categories_named(*texts: str | None) -> list[str]:
    from src.labeling.malware_taxonomy import TAXONOMY

    joined = " ".join(t for t in texts if t)
    return [c.value for c in TAXONOMY if c.value in joined]


def confirmed_categories(path: Path, final_present: dict[int, str]) -> dict:
    """Per-category miss counts and the miss rate without borderline rows,
    from the confirmed-category decision file (data/recall_categories_v2.json).
    `final_present` maps recall row -> package for rows adjudicated PRESENT;
    the file must list exactly those rows."""
    from src.labeling.malware_taxonomy import TAXONOMY

    rows = json.loads(Path(path).read_text(encoding="utf-8"))["rows"]
    listed = {r["row"]: r["package"] for r in rows}
    if listed != final_present:
        raise ValueError(f"confirmed categories do not match the PRESENT rows: "
                         f"{sorted(set(listed.items()) ^ set(final_present.items()))}")
    valid = {c.value for c in TAXONOMY}
    for r in rows:
        if not r["categories"] or set(r["categories"]) - valid:
            raise ValueError(f"row {r['row']}: bad categories {r['categories']}")
    per_cat = Counter(c for r in rows for c in r["categories"])
    per_cat_core = Counter(c for r in rows if not r["borderline"] for c in r["categories"])
    return {
        "rows": rows,
        "per_category_miss_counts": {c.value: per_cat[c.value] for c in TAXONOMY},
        "per_category_miss_counts_excluding_borderline": {c.value: per_cat_core[c.value] for c in TAXONOMY},
        "n_rows_with_k_categories": dict(sorted(Counter(len(r["categories"]) for r in rows).items())),
        "borderline_rows": [r["row"] for r in rows if r["borderline"]],
        "per_category_note": "Counts rows; a row with several missed categories counts once for each.",
    }


def labeler_report(prec1: Path, prec2: Path, rec1: Path, rec2: Path, sample: Path,
                   snapshot: Path = SNAPSHOT_V2, recall_categories: Path | None = RECALL_CATEGORIES) -> dict:
    meta = json.loads(Path(sample).read_text(encoding="utf-8"))
    records = [json.loads(l) for l in Path(snapshot).read_text(encoding="utf-8").splitlines() if l.strip()]
    p1, p2 = read_sheet(prec1, PRECISION_LABELS), read_sheet(prec2, PRECISION_LABELS)
    r1, r2 = read_sheet(rec1, RECALL_LABELS), read_sheet(rec2, RECALL_LABELS)
    p_meta = {r["row"]: r for r in meta["precision_rows"]}
    r_meta = {r["row"]: r for r in meta["recall_rows"]}
    for rows, m in ((p1, p_meta), (r1, r_meta)):
        if [(r["row"], r["package"]) for r in rows] != [(k, m[k]["package_name"]) for k in sorted(m)]:
            raise ValueError("sheet rows do not match results/annotation_sample_v2.json")

    def kappa_block(a_rows, b_rows):
        ag = agreement(a_rows, b_rows)
        return {"n_rows_used": ag["n_both_filled"], "n_rows": ag["n_rows"],
                "raw_agreement": ag["percent_agreement"], "cohen_kappa": ag["cohen_kappa"],
                "first_pass_counts": {"annotator1": dict(Counter(r["verdict"] for r in a_rows)),
                                      "annotator2": dict(Counter(r["verdict"] for r in b_rows))},
                "unsure_handling": "UNSURE is a third category in kappa; rows blank on either sheet are excluded."}

    flags = []
    # Precision (adjudicated)
    p_final = []
    for a, b in paired(p1, p2):
        v, src = final_verdict(a, b)
        if src != "adjudicated":
            flags.append({"sheet": "precision", "row": a["row"], "package": a["package"], "resolution": src,
                          "first_pass": [a["verdict"], b["verdict"]], "used": v})
        p_final.append((a, b, v))
    used = [(a, v) for a, _, v in p_final if v in ("REAL", "FALSE")]
    k_real = sum(v == "REAL" for _, v in used)
    per_cat: dict[str, dict] = {}
    for a, v in used:
        cats = p_meta[a["row"]]["categories"]
        for c in cats:
            d = per_cat.setdefault(c, {"rows_with_category": [0, 0], "single_category_rows": [0, 0]})
            d["rows_with_category"][0] += v == "REAL"
            d["rows_with_category"][1] += 1
            if len(cats) == 1:
                d["single_category_rows"][0] += v == "REAL"
                d["single_category_rows"][1] += 1
    precision_out = {
        "overall": proportion(k_real, len(used)),
        "counts": dict(Counter(v for _, _, v in p_final)),
        "per_category": {c: {k: proportion(*d[k]) for k in d} for c, d in sorted(per_cat.items())},
        "per_category_note": "Verdicts are per row; a row's verdict is attributed to every category matched on "
                             "it (rows_with_category). single_category_rows uses only rows with one category.",
        "false_rows": [
            {"row": a["row"], "package": a["package"], "adjudication_note": a["adjudication_note"],
             "matches": row_spans(records, p_meta[a["row"]]["ecosystem"], a["package"]),
             }
            for a, _, v in p_final if v == "FALSE"
        ],
    }
    for fr in precision_out["false_rows"]:
        fr["all_matches_in_tag_list"] = bool(fr["matches"]) and all(m["in_tag_list"] for m in fr["matches"])

    # Miss rate (adjudicated)
    r_final = []
    for a, b in paired(r1, r2):
        v, src = final_verdict(a, b)
        if src != "adjudicated":
            flags.append({"sheet": "recall", "row": a["row"], "package": a["package"], "resolution": src,
                          "first_pass": [a["verdict"], b["verdict"]], "used": v})
        r_final.append((a, b, v))
    n_present = sum(v == "PRESENT" for _, _, v in r_final)
    strata: dict[str, Counter] = {}
    for a, _, v in r_final:
        strata.setdefault(r_meta[a["row"]]["stratum"], Counter())[v] += 1
    miss_out = {
        "overall": proportion(n_present, len(r_final)),
        "definition": "PRESENT / all recall rows (adjudicated)",
        "counts": dict(Counter(v for _, _, v in r_final)),
        "per_stratum": {s: {"PRESENT": c["PRESENT"], "ABSENT": c["ABSENT"], "UNSURE": c["UNSURE"],
                            "n": sum(c.values()), "frame": meta["recall"]["stratum_sizes"][s]}
                        for s, c in sorted(strata.items())},
        "present_rows": [
            {"row": a["row"], "package": a["package"], "stratum": r_meta[a["row"]]["stratum"],
             "categories_named_on_sheet": categories_named(a["adjudication_note"], a["note"], b["note"]),
             "adjudication_note": a["adjudication_note"], "note1": a["note"], "note2": b["note"]}
            for a, b, v in r_final if v == "PRESENT"
        ],
        "host_fingerprint_absent": [
            {"row": a["row"], "package": a["package"], "adjudication_note": a["adjudication_note"]}
            for a, _, v in r_final if v == "ABSENT" and _HOST_FINGERPRINT.search(a["adjudication_note"] or "")
        ],
        "host_fingerprint_label": "host-fingerprint exfiltration — no category",
        "absent_rows_mentioning_host_info_in_notes": [
            {"row": a["row"], "package": a["package"], "note1": a["note"], "note2": b["note"]}
            for a, b, v in r_final if v == "ABSENT" and not _HOST_FINGERPRINT.search(a["adjudication_note"] or "")
            and (_HOST_INFO.search(a["note"]) or _HOST_INFO.search(b["note"]))
        ],
    }
    if recall_categories is not None and Path(recall_categories).exists():
        cc = confirmed_categories(recall_categories,
                                  {a["row"]: a["package"] for a, _, v in r_final if v == "PRESENT"})
        miss_out["confirmed_categories"] = cc
        n_border = len(cc["borderline_rows"])
        miss_out["excluding_borderline"] = proportion(n_present - n_border, len(r_final))
        miss_out["excluding_borderline_definition"] = (
            "borderline PRESENT rows counted as not missed: (PRESENT - borderline) / all recall rows")
    disagreements = []
    for sheet, final in (("precision", p_final), ("recall", r_final)):
        for a, b, v in final:
            if a["verdict"] != b["verdict"]:
                disagreements.append({"sheet": sheet, "row": a["row"], "package": a["package"],
                                      "annotator1": a["verdict"], "annotator2": b["verdict"], "adjudicated": v,
                                      "adjudication_note": a["adjudication_note"]})
    return {
        "inputs": {"annotator1": [str(Path(prec1).name), str(Path(rec1).name)],
                   "annotator2": [str(Path(prec2).name), str(Path(rec2).name)],
                   "adjudication": "annotator 1's sheets (Adjudicated / Adjudication note lines)"},
        "kappa_first_pass": {"precision_sheet": kappa_block(p1, p2), "recall_sheet": kappa_block(r1, r2)},
        "labeler_precision": precision_out,
        "labeler_miss_rate": miss_out,
        "disagreements": disagreements,
        "resolution_flags": flags,
    }


# --- CLI ---------------------------------------------------------------------

def run(prec1: Path, prec2: Path, rec1: Path, rec2: Path, sample: Path) -> dict:
    meta = json.loads(Path(sample).read_text(encoding="utf-8"))
    n_pos, n_neg = meta["n_dv_positive"], meta["recall"]["frame"]
    p_rows = [read_sheet(prec1, PRECISION_LABELS), read_sheet(prec2, PRECISION_LABELS)]
    r_rows = [read_sheet(rec1, RECALL_LABELS), read_sheet(rec2, RECALL_LABELS)]
    out = {"agreement": {"precision_sheet": agreement(*p_rows), "recall_sheet": agreement(*r_rows)},
           "by_annotator": {}}
    for i in (0, 1):
        pr, mr = precision(p_rows[i]), miss_rate(r_rows[i])
        out["by_annotator"][f"annotator{i + 1}"] = {
            "precision": pr, "miss_rate": mr,
            "recall": recall_estimate(n_pos, pr["excluding_unsure"], n_neg, mr["excluding_unsure"]),
        }
    return out


def _fmt(prop: dict) -> str:
    if prop["p"] is None:
        return f"{prop['k']}/{prop['n']} (no rows)"
    lo, hi = prop["wilson95"]
    return f"{prop['k']}/{prop['n']} = {prop['p']:.3f} [{lo:.3f}, {hi:.3f}]"


def main(argv=None) -> dict:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--precision", nargs=2, type=Path, metavar=("ANNOTATOR1", "ANNOTATOR2"),
                    default=[REPORTS / "annotation_precision_v2.md", REPORTS / "annotation_precision_v2_annotator2.md"])
    ap.add_argument("--recall", nargs=2, type=Path, metavar=("ANNOTATOR1", "ANNOTATOR2"),
                    default=[REPORTS / "annotation_recall_v2.md", REPORTS / "annotation_recall_v2_annotator2.md"])
    ap.add_argument("--sample", type=Path, default=SAMPLE)
    ap.add_argument("--out", type=Path, default=OUT)
    ap.add_argument("--labeler-out", type=Path, default=LABELER_OUT)
    ap.add_argument("--snapshot", type=Path, default=SNAPSHOT_V2)
    ap.add_argument("--recall-categories", type=Path, default=RECALL_CATEGORIES)
    args = ap.parse_args(argv)
    out = run(*args.precision, *args.recall, args.sample)
    for sheet, a in out["agreement"].items():
        k = "n/a" if a["cohen_kappa"] is None else f"{a['cohen_kappa']:.3f}"
        print(f"{sheet}: {a['n_both_filled']}/{a['n_rows']} rows filled by both, kappa {k}, "
              f"{len(a['disagreements'])} disagreements")
    for who, d in out["by_annotator"].items():
        rec = d["recall"]
        rtxt = "n/a" if rec["recall"] is None else \
            f"{rec['recall']:.3f} [{rec['interval'][0]:.3f}, {rec['interval'][1]:.3f}]"
        print(f"{who}: precision {_fmt(d['precision']['excluding_unsure'])}; "
              f"miss rate {_fmt(d['miss_rate']['excluding_unsure'])}; recall {rtxt}")
    args.out.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    print(f"Written: {args.out}")
    if any(r["adjudicated"] for r in read_sheet(args.precision[0], PRECISION_LABELS)
           + read_sheet(args.recall[0], RECALL_LABELS)):
        rep = labeler_report(*args.precision, *args.recall, args.sample, args.snapshot, args.recall_categories)
        args.labeler_out.write_text(json.dumps(rep, indent=2) + "\n", encoding="utf-8")
        print(f"Written: {args.labeler_out}")
    return out


if __name__ == "__main__":
    main()
