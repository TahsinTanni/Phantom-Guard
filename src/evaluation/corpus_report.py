"""
Full v2 analysis and the v1-vs-v2 comparison (research_log 5.19).

    python run_check.py                                   # v1 main
    python run_check.py --text-source ghsa                # v1 GHSA-only
    python run_check.py --snapshot v2                     # v2 main
    python run_check.py --snapshot v2 --text-source ghsa  # v2 GHSA-only
    python -m src.evaluation.agreement                    # labeler validation
    python -m src.evaluation.corpus_report

Reads those outputs (it computes no new test statistics except the
misclassification correction) and writes results/analysis_v2.json:
Table I (grammar flag rate by set), Table II (every specification, v1 and
v2), power at the achieved n, the campaign-size distribution, and the main
grammar odds ratio corrected for outcome misclassification
(src/statistics/misclassification.py) with the measured precision and miss
rate, also with the miss rate excluding borderline recall rows.
"""

from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path

from src.evaluation.agreement import wilson
from src.statistics.misclassification import probabilistic_correction, simple_correction

ROOT = Path(__file__).resolve().parents[2]
RES = ROOT / "results"
OUT = RES / "analysis_v2.json"
FILES = {
    "v1": {"main": RES / "power_campaign_level.json", "ghsa": RES / "power_campaign_level__text-ghsa__group-any.json",
           "csv": RES / "campaigns.csv"},
    "v2": {"main": RES / "power_campaign_level__v2.json",
           "ghsa": RES / "power_campaign_level__text-ghsa__group-any__v2.json", "csv": RES / "campaigns__v2.csv"},
}


def _fisher(r: dict) -> dict:
    return {"n": r["n_total"], "table": r["table_2x2"], "or": r["odds_ratio"], "ci": r["odds_ratio_ci_95"],
            "p": r["p_value"]}


def _cmh(r: dict) -> dict:
    return {"n": r["n_total"], "or": r["common_odds_ratio"], "ci": r["common_odds_ratio_ci_95"], "p": r["p_value"]}


def _term(model: dict, name: str) -> dict:
    t = model["terms"][name]
    return {"n": model["n"], "or": t["odds_ratio"], "ci": [t["or_ci_low"], t["or_ci_high"]], "p": t["p_value"],
            "converged": model["converged"]}


def table_ii(main: dict, ghsa: dict) -> dict:
    s, rep = main["section_5_6"], main["reporters_d2"]
    sens = rep["logit_sensitivity"]
    models = {"d": rep["logit"], "a": sens["a_drop_amazon"], "b": sens["b_drop_n_reporters"],
              "c": sens["c_a_plus_boilerplate_kam193"]}
    out = {
        "pooled_fisher": _fisher(s["pooled"]),
        "npm_fisher": _fisher(s["by_ecosystem"]["npm"]),
        "pypi_fisher": _fisher(s["by_ecosystem"]["pypi"]),
        "cmh_ecosystem": _cmh(s["cmh"]),
        "cmh_ecosystem_x_n_reporters": _cmh(rep["cmh"]["ecosystem_x_n_reporters"]["result"]),
        "ghsa_only_fisher": _fisher(ghsa["section_5_6"]["pooled"]),
        "ghsa_only_cmh": _cmh(ghsa["section_5_6"]["cmh"]),
    }
    for k, m in models.items():
        out[f"logit_{k}_grammar"] = _term(m, "grammar_flag")
        out[f"logit_{k}_reporter_terms"] = {name: _term(m, name) for name in m["terms"]
                                            if name not in ("Intercept", "grammar_flag", "C(ecosystem)[T.pypi]")}
        out[f"logit_{k}_llr_p"] = m["llr_p_value"]
    return out


def size_distribution(path: Path) -> dict:
    rows = list(csv.DictReader(open(path, encoding="utf-8")))
    sizes = [len(r["member_packages"].split(";")) for r in rows]
    by_eco = {e: Counter(len(r["member_packages"].split(";")) for r in rows if r["ecosystem"] == e)
              for e in ("npm", "pypi")}
    return {"n_campaigns": len(rows), "n_packages": sum(sizes),
            "by_ecosystem": {e: {"campaigns": sum(c.values()), "packages": sum(k * v for k, v in c.items())}
                             for e, c in by_eco.items()},
            "size_counts": dict(sorted(Counter(sizes).items())),
            "largest": sorted(sizes, reverse=True)[:10],
            "singletons": sizes.count(1),
            "signature_types": dict(Counter(r["signature_type"] for r in rows)),
            "grammar_flagged": sum(int(r["grammar_flag"]) for r in rows),
            "dv_positive": sum(int(r["mechanism_label"]) for r in rows)}


def table_i(v1_csv: Path, v2_csv: Path) -> list[dict]:
    gv = json.loads((RES / "grammar_validation.json").read_text())["sets"]
    rows = [("LLM-hallucinated names", gv["hallucinated"]["all"]["flag_count"], gv["hallucinated"]["all"]["n"]),
            ("Benign top-5,000 PyPI", gv["benign_top5000"]["pypi"]["flag_count"], gv["benign_top5000"]["pypi"]["n"]),
            ("Benign top-5,000 npm", gv["benign_top5000"]["npm"]["flag_count"], gv["benign_top5000"]["npm"]["n"])]
    for label, path in (("Malware campaigns v1", v1_csv), ("Malware campaigns v2", v2_csv)):
        r = list(csv.DictReader(open(path, encoding="utf-8")))
        rows.append((label, sum(int(x["grammar_flag"]) for x in r), len(r)))
    return [{"set": s, "flagged": k, "n": n, "rate": k / n, "wilson95": wilson(k, n)} for s, k, n in rows]


def misclassification(v2_main: dict, v2_csv: Path) -> dict:
    lab = json.loads((RES / "labeler_agreement_v2.json").read_text())
    prec, miss = lab["labeler_precision"]["overall"], lab["labeler_miss_rate"]
    miss_b = miss["excluding_borderline"]
    table = v2_main["section_5_6"]["pooled"]["table_2x2"]
    rows = list(csv.DictReader(open(v2_csv, encoding="utf-8")))
    no_text = tuple(sum(1 for r in rows if int(r["no_text"]) and int(r["grammar_flag"]) == g
                        and not int(r["mechanism_label"])) for g in (1, 0))
    out = {"observed_table": table, "observed_or": v2_main["section_5_6"]["pooled"]["odds_ratio"],
           "no_text_negatives_flagged_unflagged": no_text,
           "method": "predictive-value back-calculation (Lash, Fox & Fink 2021, ch. 6): true positives per "
                     "grammar row = labeler positives * precision + eligible labeler negatives * miss rate; "
                     "no-text negatives get miss rate 0; assumes equal predictive values in both rows"}
    for key, m in (("main_miss_17_40", miss["overall"]), ("miss_excluding_borderline_14_40", miss_b)):
        out[key] = {"simple": simple_correction(table, prec["p"], m["p"], no_text),
                    "probabilistic": probabilistic_correction(table, prec["k"], prec["n"], m["k"], m["n"], no_text)}
    # Non-differential check: predictive values by grammar flag in the validation samples.
    sample = json.loads((RES / "annotation_sample_v2.json").read_text())
    flag_of = {m: int(r["grammar_flag"]) for r in rows for m in r["member_packages"].split(";")}
    pv = {"precision": Counter(), "miss": Counter()}
    prec_rows = {(x["row"]): x for x in sample["precision_rows"]}
    rec_rows = {(x["row"]): x for x in sample["recall_rows"]}
    false_rows = {r["row"] for r in lab["labeler_precision"]["false_rows"]}
    present_rows = {r["row"] for r in lab["labeler_miss_rate"]["present_rows"]}
    for row, x in prec_rows.items():
        g = max(flag_of[m] for m in x["campaign_members"])
        pv["precision"][(g, row not in false_rows)] += 1
    for row, x in rec_rows.items():
        g = max(flag_of[m] for m in x["campaign_members"])
        pv["miss"][(g, row in present_rows)] += 1
    out["nondifferential_check"] = {
        "precision_flagged": wilson_block(pv["precision"][(1, True)], pv["precision"][(1, True)] + pv["precision"][(1, False)]),
        "precision_unflagged": wilson_block(pv["precision"][(0, True)], pv["precision"][(0, True)] + pv["precision"][(0, False)]),
        "miss_flagged": wilson_block(pv["miss"][(1, True)], pv["miss"][(1, True)] + pv["miss"][(1, False)]),
        "miss_unflagged": wilson_block(pv["miss"][(0, True)], pv["miss"][(0, True)] + pv["miss"][(0, False)]),
    }
    return out


def wilson_block(k: int, n: int) -> dict:
    return {"k": k, "n": n, "p": (k / n if n else None), "wilson95": wilson(k, n)}


def main() -> dict:
    data = {v: {k: json.loads(FILES[v][k].read_text()) for k in ("main", "ghsa")} for v in FILES}
    out = {
        "table_i": table_i(FILES["v1"]["csv"], FILES["v2"]["csv"]),
        "table_ii": {v: table_ii(data[v]["main"], data[v]["ghsa"]) for v in FILES},
        "power": {v: data[v]["main"]["power"] for v in FILES},
        "campaign_sizes": {v: size_distribution(FILES[v]["csv"]) for v in FILES},
        "sensitivity": {v: data[v]["main"]["sensitivity"] for v in FILES},
        "misclassification_v2": misclassification(data["v2"]["main"], FILES["v2"]["csv"]),
    }
    OUT.write_text(json.dumps(out, indent=2, default=str) + "\n", encoding="utf-8")
    print(f"Written: {OUT}")
    return out


if __name__ == "__main__":
    main()
